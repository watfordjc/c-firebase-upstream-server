/* firebase-upstream-server.c
** Firebase upstream messaging XMPP client (app server)
**
** Copyright (C) 2019 John Cook
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
** This program is licensed under the MIT licence.
**
** This program is based on bot.c, an example provided to libstrophe
** by Matthew Wild <mwild1@gmail.com>.
*/

/* Standard Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
/* libstrophe */
#include <strophe.h>
/* libconfig */
#include <libconfig.h>
/* libjson-c */
#include <json-c/json.h>

char *CONFIG_FILE = "";
char LINE_TERMINATOR = '\n';
int use_record_separator = 0;
int use_length_prefix = 0;
int use_concat_output = 0;

/* Limit number of simultaneous outbound connections to 1 */
/* max_logins should equal the size of the arrays logins[] and connections[] */
#define MAX_LOGINS 1
struct config_settings *logins[MAX_LOGINS];
xmpp_conn_t *connections[MAX_LOGINS] = {NULL};

int logins_count = 0;

struct config_settings
{
  int enabled;
  const char *host;
  unsigned short port;
  long flags;
  const char *jid;
  const char *pass;
  struct config_setting_t *pointer;
};
struct config_t conf;
struct config_t *config;

int command_options(int argc, char **argv);

void open_config();
void close_config();
void handle_sigint();

int get_root_element_count(config_t *config, char *name, config_setting_t *config_element);
int get_element_count(config_setting_t *config, char *name, config_setting_t *config_element);
int get_config_int(config_setting_t *setting, char *name);
int get_config_bool(config_setting_t *setting, char *name);
const char *get_config_string(config_setting_t *setting, char *name);

/* libconfig < v1.5 - renamed function */
#if (LIBCONFIG_VER_MAJOR <= 1) && (LIBCONFIG_VER_MINOR <= 4)
#define config_setting_lookup config_lookup_from
#endif

long get_tls_flags(const char *tls);
unsigned short get_port(int port);

void servers_iterate(void);
void logins_iterate(int serverInt, struct config_settings server_login, struct config_setting_t *server_element);

/* OpenSSL function declarations for cleanup */
int FIPS_mode_set();
void CRYPTO_set_locking_callback();
void CRYPTO_set_id_callback();
void SSL_COMP_free_compression_methods();
int ENGINE_cleanup();
int CONF_modules_free();
int CONF_modules_unload();
void COMP_zlib_cleanup();
int ERR_free_strings();
void EVP_cleanup();
void CRYPTO_cleanup_all_ex_data();
void ERR_remove_state();

int verbose;

void print_formatted_json(json_object *jobj)
{
  /* Concatenated: No start character, string, no end character */
  if (use_concat_output == 1) {
    fprintf(stdout, "%s", json_object_get_string(jobj));
  }
  /* Record-separated: Start character, string, end character */
  else if (use_record_separator == 1) {
    fprintf(stdout, "%c%s%c", 0x1e, json_object_get_string(jobj), LINE_TERMINATOR);
  }
  /* Length-prefixed: Start integer, string, no end character */
  else if (use_length_prefix == 1) {
    fprintf(stdout, "%d%s", (int) strlen(json_object_get_string(jobj)), json_object_get_string(jobj));
  }
  /* Line-delimited: No start character, string, end character */
  /* Nul-terminated: No start character, string, end character */
  /* else if (use_concat_output == 0 && use_record_separator == 0 && use_length_prefix == 0) { */
  else {
    fprintf(stdout, "%s%c", json_object_get_string(jobj), LINE_TERMINATOR);
  }
  /* Flush output */
  fflush(stdout);
}

void send_ack(xmpp_ctx_t *ctx, xmpp_conn_t * const conn, json_object *jobj)
{
  /* Initialise new JSON objects */
  json_object *from = NULL;
  json_object *message_id = NULL;
  /* Initialise new XMPP elements */
  xmpp_stanza_t *reply_message = xmpp_stanza_new(ctx);
  xmpp_stanza_t *reply_gcm = xmpp_stanza_new(ctx);
  xmpp_stanza_t *reply_text = xmpp_stanza_new(ctx);
  /* Create a new JSON object */
  json_object *ack = json_object_new_object();
  /* Create a new JSON string value of "ack" */
  json_object *message_reply_type = json_object_new_string("ack");

  /* Get "from": in inbound message, and add to *ack as "to": */
  json_object_object_get_ex(jobj, "from", &from);
  json_object_object_add(ack, "to", json_object_get(from));

  /* Get "message_id": from inbound message and add to *ack */
  json_object_object_get_ex(jobj, "message_id", &message_id);
  json_object_object_add(ack, "message_id", json_object_get(message_id));

  /* Add JSON string "ack" to *ack as new key "message_type": */
  json_object_object_add(ack, "message_type", json_object_get(message_reply_type));

  /* Create <message id=""></message> */
  xmpp_stanza_set_name(reply_message, "message");
  xmpp_stanza_set_attribute(reply_message, "id", "");

  /* Create <gcm xmlns="google:mobile:data"></gcm>  */
  xmpp_stanza_set_name(reply_gcm, "gcm");
  xmpp_stanza_set_ns(reply_gcm, "google:mobile:data");
  /* Insert <gcm></gcm> inside <message></message> and then free */
  xmpp_stanza_add_child(reply_message, reply_gcm);
  xmpp_stanza_release(reply_gcm);

  /* Convert JSON into XMPP text (for <element>text</element>) */
  xmpp_stanza_set_text(reply_text, json_object_get_string(ack));
  /* Insert JSON (XMPP text) inside <gcm></gcm> and then free */
  xmpp_stanza_add_child(reply_gcm, reply_text);
  xmpp_stanza_release(reply_text);

  /* Send ack */
  xmpp_send(conn, reply_message);
  /* Free <message></message> */
  xmpp_stanza_release(reply_message);
  /* Free created JSON objects */
  json_object_put(message_reply_type);
  json_object_put(ack);
}

int fcm_upstream_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
  xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;
  xmpp_stanza_t *gcm;
  char *intext;
  struct json_tokener *tok;
  json_object *jobj, *message_type, *control_type;
  enum json_tokener_error jerr;
  json_bool not_a_message;
  int stringlen;

  gcm = xmpp_stanza_get_child_by_name(stanza, "gcm");
  if (gcm == NULL) {
    return 1;
  }

  intext = xmpp_stanza_get_text(gcm);

  tok = json_tokener_new();
  jobj = NULL;
  stringlen = 0;
  do
  {
    stringlen = strlen(intext);
    jobj = json_tokener_parse_ex(tok, intext, stringlen);
  } while ((jerr = json_tokener_get_error(tok)) == json_tokener_continue);
  if (jerr != json_tokener_success)
  {
    if (jobj == NULL) {
      fprintf(stderr, "from_fcm error: Invalid JSON\n");
      fprintf(stderr, "from_fcm incoming message from %s: %s\n", xmpp_stanza_get_from(stanza), intext);
    } else {
      fprintf(stderr, "from_fcm error: %s\n", json_tokener_error_desc(jerr));
    }
    /* Handle errors, as appropriate for your application. */
    json_object_put(jobj);
    json_tokener_free(tok);
    xmpp_free(ctx, intext);
    return 1;
  }
  if (tok->char_offset < stringlen) /* XXX shouldn't access internal fields */
  {
    /* Handle extra characters after parsed object as desired.
    *   e.g. issue an error, parse another object from that point, etc...
    */
    /* FCM upstream should only have one JSON object per message. */
  }
  /* Success, use jobj here. */
  print_formatted_json(jobj);

  message_type = NULL;
  not_a_message = json_object_object_get_ex(jobj, "message_type", &message_type);
  if (not_a_message == TRUE) {
    fprintf(stderr, "from_fcm: This is a not a message, it is a %s\n", json_object_get_string(message_type));
    if (strcmp("control", json_object_get_string(message_type)) == 0) {
      /* FCM control message, check control_type */
      control_type = NULL;
      json_object_object_get_ex(jobj, "control_type", &control_type);
      /* If control type is CONNECTION_DRAINING, announce to stderr */
      if (strcmp("CONNECTION_DRAINING", json_object_get_string(control_type)) == 0) {
        fprintf(stderr, "DEBUG: CONNECTION_DRAINING\n");
      }
    }
    json_object_put(jobj);
  } else {
    fprintf(stderr, "from_fcm: This is a message.\n");

    send_ack(ctx, conn, jobj);

    json_object_put(jobj);

  }

  json_tokener_free(tok);
  xmpp_free(ctx, intext);
  /* xmpp_disconnect(conn); */

  return 1;
}

/* define a handler for connection events */
void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status,
  const int error, xmpp_stream_error_t * const stream_error,
  void * const userdata)
{
  xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

  if (status == XMPP_CONN_CONNECT) {
    fprintf(stderr, "DEBUG: CONNECTED\n");
    xmpp_handler_add(conn, fcm_upstream_handler, "google:mobile:data", "message", NULL, ctx);

  } else {
    fprintf(stderr, "DEBUG: DISCONNECTED\n");
    xmpp_stop(ctx);
  }
}

int main(int argc, char **argv)
{
  struct config_settings *loginPtr;
  struct config_settings login;
  xmpp_ctx_t *ctx;
  xmpp_conn_t *conn;
  xmpp_log_t *log;

  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);
  /* Close connections on SIGINT */
  signal(SIGINT, handle_sigint);

  #ifdef BE_VERBOSE
  verbose = 1;
  #endif

  command_options(argc, argv);
  open_config();

  /*
  * Iterate through configuration file recursively via servers_iterate() and logins_iterate().
  * logins_iterate() populates *logins[].
  */
  servers_iterate();

  if (logins_count != 1)
  {
    fprintf(stderr, "conf: This version of the program requires one login.\n");
    close_config();
    exit(1);
  }
  loginPtr = logins[0];
  login = *loginPtr;

  /* init library */
  xmpp_initialize();

  /* create a context */
  log = verbose == 1 ? xmpp_get_default_logger(XMPP_LEVEL_DEBUG) : xmpp_get_default_logger(XMPP_LEVEL_INFO); /* pass NULL instead to silence output */

  ctx = xmpp_ctx_new(NULL, log);

  /* create a connection */
  conn = xmpp_conn_new(ctx);
  /* store pointer to connection in array */
  connections[0] = conn;


  xmpp_conn_set_flags(conn, login.flags);

  /* setup authentication information */
  xmpp_conn_set_jid(conn, login.jid);
  xmpp_conn_set_pass(conn, login.pass);

  /* initiate connection */
  xmpp_connect_client(conn, login.host, login.port, conn_handler, ctx);

  /* enter the event loop -
  our connect handler will trigger an exit */
  xmpp_run(ctx);

  /* cleanup OpenSSL */
  FIPS_mode_set(0);
  CRYPTO_set_locking_callback(NULL);
  CRYPTO_set_id_callback(NULL);
  SSL_COMP_free_compression_methods();
  ENGINE_cleanup();
  CONF_modules_free();
  CONF_modules_unload();
  COMP_zlib_cleanup();
  ERR_free_strings();
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();

  /* release our connection and context */
  xmpp_conn_release(conn);
  connections[0] = NULL;
  xmpp_ctx_free(ctx);

  /* cleanup OpenSSL (must do for every thread) */
  ERR_remove_state(0);

  /* final shutdown of the library */
  xmpp_shutdown();

  /* close config file */
  close_config();

  return 0;
}

int command_options(int argc, char **argv)
{
  /* handle command line arguments */
  int c;
  while (1)
  {
    /*
    * Values returned are char, so start at 1001 for long options without short
    *  equivalent so they don't interfere with short options (e.g. 'z' = 122).
    * If a decision is made to later add a short option, change the number in
    *  the array and the case statement for that option (e.g. replacing 1008 with '4'.
    */
    static struct option long_options[] =
    {
      {"null", no_argument, 0, 'Z'},
      {"config", required_argument, 0, 1001},
      {"concat", no_argument, &use_concat_output, 1},
      {"seq", no_argument, &use_record_separator, 1},
      {"len-prefixed", no_argument, &use_length_prefix, 1},
      {"verbose", no_argument, 0, 'v'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}
    };

    int option_index = 0;
    c = getopt_long(argc, argv, "Zhv", long_options, &option_index);
    if (c == -1)
    {
      break;
    }

    switch (c)
    {
      case 0:
        /* if this options, set a flag, do nothing else now */
        if (long_options[option_index].flag != 0)
        {
          break;
        }
        break;
      case 1001:
        CONFIG_FILE = optarg;
        break;
      case 'Z':
        LINE_TERMINATOR = '\0';
        break;
      case 'v':
        verbose = 1;
        break;
      case 'h':
      default:
        fprintf(stderr, "Usage: %s [options]\n", argv[0]);
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  --config <file>\n");
        fprintf(stderr, "    Path to configuration file.\n");
        fprintf(stderr, "  -Z, --null\n");
        fprintf(stderr, "    Separate output JSON with NUL instead of new line character.\n");
        fprintf(stderr, "  --concat\n");
        fprintf(stderr, "    Use concatenated JSON output.\n");
        fprintf(stderr, "  --len-prefixed\n");
        fprintf(stderr, "    Use length-prefixed JSON output.\n");
        fprintf(stderr, "  --seq\n");
        fprintf(stderr, "    Use application/json-seq output.\n");
        fprintf(stderr, "  -v, --verbose\n");
        fprintf(stderr, "    Use DEBUG level of libstrophe logging.\n");
        fprintf(stderr, "  -h, --help\n");
        fprintf(stderr, "    Display this information.\n");
        exit(0);
        break;
    }
  }
  return 0;
}

void open_config()
{
  int loaded_config;
  if (strlen(CONFIG_FILE) == 0)
  {
    fprintf(stderr, "conf: No configuration file specified.\n");
    exit(1);
  }

  config = &conf;
  config_init(config);

  loaded_config = config_read_file(config, CONFIG_FILE);
  if (loaded_config != 1)
  {
    fprintf(stderr, "conf: Error reading config file %s. Error on line %d: %s\n", config_error_file(config), config_error_line(config), config_error_text(config));
    config_destroy(config);
  }
}

void close_config()
{
  struct config_settings *loginPtr;
  /* Cleanup before config_destroy() */
  int i;
  for (i = 0; i < logins_count; i++)
  {
    loginPtr = logins[i];
    free(loginPtr);
  }
  config_destroy(config);
}

void servers_iterate(void)
{
  /* Loop through servers */
  struct config_setting_t conf_servers;
  struct config_setting_t *config_servers = &conf_servers;
  int server_count = get_root_element_count(config, "servers", config_servers);
  int i;

  #ifdef BE_VERBOSE
  fprintf(stderr, "conf: Number of servers: %d\n", server_count);
  #endif

  for (i = 0; i < server_count; i++)
  {
    struct config_setting_t *server_element = config_setting_get_elem(config_servers, i);
    struct config_settings server_login = {0};
    int server_enabled;
    if (server_element == NULL)
    {
      continue;
    }
    server_login.pointer = server_element;

    server_enabled = get_config_bool(server_element, "enabled");
    if (server_enabled == 0)
    {
      fprintf(stderr, "conf: Server %d is not enabled.\n", i);
      continue;
    }
    else if (server_enabled > 0)
    {
      server_login.enabled = server_enabled;
      server_login.host = get_config_string(server_element, "host");
      server_login.flags = get_tls_flags(get_config_string(server_element, "tls"));
      server_login.port = get_port(get_config_int(server_element, "port"));

      #ifdef BE_VERBOSE
      fprintf(stderr, "servers[%d].enabled = %d\n", i, server_login.enabled);
      fprintf(stderr, "servers[%d].host = %s\n", i, server_login.host);
      fprintf(stderr, "servers[%d].port = %d\n", i, (int) server_login.port);
      fprintf(stderr, "servers[%d].flags = %d\n", i, (int) server_login.flags);
      #endif

      logins_iterate(i, server_login, server_element);
    }
  }
}

void logins_iterate(int serverNumber, struct config_settings server_login, struct config_setting_t *server_element)
{
  /*
  * Loop through logins.
  */

  struct config_setting_t *conf_logins = config_setting_lookup(server_element, "logins");
  int login_count, i;
  struct config_settings *loginPtr;
  if (conf_logins == NULL)
  {
    fprintf(stderr, "conf: No logins defined for server %d.\n", serverNumber);
    return;
  }
  login_count = config_setting_length(conf_logins);
  #ifdef BE_VERBOSE
  fprintf(stderr, "conf: Number of logins for server %d: %d\n", serverNumber, login_count);
  #endif


  for (i = 0; i < login_count; i++)
  {
    struct config_setting_t *login_element = config_setting_get_elem(conf_logins, i);
    if (login_element == NULL)
    {
      continue;
    }

    loginPtr = NULL;
    loginPtr = (struct config_settings *) malloc(sizeof(struct config_settings));
    #ifdef BE_VERBOSE
    fprintf(stderr, "Pointer loginPtr: %p\n", (void *) loginPtr);
    #endif
    memcpy(loginPtr, &server_login, sizeof(struct config_settings));
    loginPtr->pointer = login_element;
    loginPtr->jid = get_config_string(login_element, "jid");
    loginPtr->pass = get_config_string(login_element, "pass");

    #ifdef BE_VERBOSE
    fprintf(stderr, "servers[%d].logins[%d].jid length = %d\n", serverNumber, i, (int) strlen(loginPtr->jid));
    fprintf(stderr, "servers[%d].logins[%d].pass length = %d\n", serverNumber, i, (int) strlen(loginPtr->pass));
    fprintf(stderr, "servers[%d].logins[%d].pointer = %p\n", serverNumber, i, (void *) loginPtr->pointer);
    #endif

    if (logins_count < MAX_LOGINS)
    {
      logins[logins_count] = loginPtr;
      logins_count++;
    }
    else
    {
      fprintf(stderr, "conf: Compiled with only %d maximum logins, configuration file contains at least %d.\n", MAX_LOGINS, logins_count+1);
      fprintf(stderr, "conf: Please modify '#define MAX_LOGINS %d' in source code and recompile.\n", MAX_LOGINS);
      config_destroy(config);
      exit(1);
    }
  }
}

/*
* Function get_root_element_count:
*       * Returns number (int) of elements in list 'name' in configuration 'config'.
*       * Updates pointer '*config_element' to point to element 'name'.
*
* config_t *config : pointer to parsed config
* char *name : pointer to name of element
* config_setting_t *conf_element : pointer to element
*/
int get_root_element_count(config_t *config, char *name, config_setting_t *config_element)
{
  config_setting_t *conf_element = config_lookup(config, name);
  if (conf_element == NULL)
  {
    fprintf(stderr, "conf: No %s found in configuration file.\n", name);
    exit(1);
  }
  else
  {
    *config_element = *conf_element;
    return config_setting_length(config_element);
  }
}

/*
* Function get_element_count:
*       * Returns number (int) of elements in list 'name' in configuration setting 'config_setting'.
*       * Updates pointer '*config_element' to point to element 'name'.
*
* config_setting_t *config : pointer to parsed config setting
* char *name : pointer to name of element
* config_setting_t *conf_element : pointer to element
*/
int get_element_count(config_setting_t *config_setting, char *name, config_setting_t *config_element)
{
  config_setting_t *conf_element = config_setting_lookup(config_setting, name);
  if (conf_element == NULL)
  {
    fprintf(stderr, "conf: No %s found in configuration file for this account.\n", name);
    return 0;
  }
  else {
    *config_element = *conf_element;
    return config_setting_length(config_element);
  }
}

/*
* Function get_config_int looks up the integer value of 'name'
*  in the configuration setting 'setting' and returns the integer.
* -1 is returned if 'name' does not exist.
*/
int get_config_int(config_setting_t *setting, char *name)
{
  config_setting_t *setting_pointer = NULL;
  setting_pointer = config_setting_lookup(setting, name);
  if (setting_pointer != NULL)
  {
    return config_setting_get_int(setting_pointer);
  }
  else
  {
    return -1;
  }
}

/*
* Function get_config_bool looks up the boolean value of 'name'
*  in the configuration setting 'setting' and returns it as an integer.
* -1 is returned if 'name' does not exist.
*/
int get_config_bool(config_setting_t *setting, char *name)
{
  config_setting_t *setting_pointer = NULL;
  setting_pointer = config_setting_lookup(setting, name);
  if (setting_pointer != NULL)
  {
    return config_setting_get_bool(setting_pointer);
  }
  else
  {
    return -1;
  }
}

/*
* Function get_config_string looks up the string value of 'name'
*  in the configuration setting 'setting' and returns the string.
* NULL is returned if 'name' does not exist.
*/
const char *get_config_string(config_setting_t *setting, char *name)
{
  config_setting_t *setting_pointer = NULL;
  setting_pointer = config_setting_lookup(setting, name);
  if (setting_pointer != NULL)
  {
    return config_setting_get_string(setting_pointer);
  }
  else
  {
    return NULL;
  }
}

/*
* Function get_tls_flags converts a configuration file string to a
*  long for libstrophe.
*/
long get_tls_flags(const char *tls)
{
  long flags = 0;
  /* Mandatory StartTLS is the default and fallback option as that is the
  *   assumed server configuration per federated XMPP requirements
  *   and RFC 7590. It can be explicitly configured in a config file with:
  *     tls="starttls";
  * Mandatory TLS (legacy/old style/non-StartTLS) is an option:
  *     tls="tls";
  * Optional StartTLS (plaintext fallback) is an option that can be used with:
  *     tls="optional";
  * Plaintext is also a configurable option:
  *     tls="plaintext";
  */
  #ifdef BE_VERBOSE
  fprintf(stderr, "tls: %s\n", tls);
  #endif

  if (
      (tls == NULL)
      || (strcmp("starttls", tls) == 0)
      || (strcmp("", tls) == 0)
    ) {
      flags |= XMPP_CONN_FLAG_MANDATORY_TLS;
    } else if (
      (strcmp("tls", tls) == 0)
    ) {
      flags |= XMPP_CONN_FLAG_LEGACY_SSL;
      flags |= XMPP_CONN_FLAG_MANDATORY_TLS;
    } else if (strcmp("plaintext", tls) == 0) {
        flags |= XMPP_CONN_FLAG_DISABLE_TLS;
    } else if (strcmp("optional", tls) == 0) {
        flags = 0;
    } else {
      flags |= XMPP_CONN_FLAG_MANDATORY_TLS;
    }
  return flags;
}

/*
* Function get_port converts a configuration file integer to a short int.
*/
unsigned short get_port(int port)
{
  if (port <= 0 || port > 65535) {
    return 0;
  } else {
    return (unsigned short) port;
  }
}

/*
* Handle SIGINT signal - rely on xmpp_run() returning after connections closed
*/
void handle_sigint()
{
  int i;
  for (i = 0; i < MAX_LOGINS; i++) {
    if (connections[i] != NULL) {
      xmpp_disconnect(connections[i]);
    }
  }
}
