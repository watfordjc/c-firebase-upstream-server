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

/* simple bot example
**
** This program is based on an example provided to libstrophe
** by Matthew Wild <mwild1@gmail.com>.
**
** This bot responds to basic messages and iq version requests.
*/

/* Standard Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
/* libstrophe */
#include <strophe.h>
/* libconfig */
#include <libconfig.h>

char *CONFIG_FILE = "";

int max_logins = 1;
struct config_settings *logins[1];
int logins_count = 0;

struct config_settings
{
  int enabled;
  const char *host;
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

int get_root_element_count(config_t *config, char *name, config_setting_t *config_element);
int get_element_count(config_setting_t *config, char *name, config_setting_t *config_element);
int get_config_int(config_setting_t *setting, char *name);
int get_config_bool(config_setting_t *setting, char *name);
const char *get_config_string(config_setting_t *setting, char *name);

/* Uncomment if libconfig < v1.5 - renamed function */
/* #define config_setting_lookup config_lookup_from */

long get_tls_flags(const char *tls);

void servers_iterate();
void logins_iterate(int serverInt, struct config_settings server_login, struct config_setting_t *server_element);

int version_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
  xmpp_stanza_t *reply, *query, *name, *version, *text;
  const char *ns;
  xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;

  printf("Received version request from %s\n", xmpp_stanza_get_from(stanza));

  reply = xmpp_stanza_reply(stanza);
  xmpp_stanza_set_type(reply, "result");

  query = xmpp_stanza_new(ctx);
  xmpp_stanza_set_name(query, "query");
  ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
  if (ns) {
    xmpp_stanza_set_ns(query, ns);
  }

  name = xmpp_stanza_new(ctx);
  xmpp_stanza_set_name(name, "name");
  xmpp_stanza_add_child(query, name);
  xmpp_stanza_release(name);

  text = xmpp_stanza_new(ctx);
  xmpp_stanza_set_text(text, "libstrophe example bot");
  xmpp_stanza_add_child(name, text);
  xmpp_stanza_release(text);

  version = xmpp_stanza_new(ctx);
  xmpp_stanza_set_name(version, "version");
  xmpp_stanza_add_child(query, version);
  xmpp_stanza_release(version);

  text = xmpp_stanza_new(ctx);
  xmpp_stanza_set_text(text, "1.0");
  xmpp_stanza_add_child(version, text);
  xmpp_stanza_release(text);

  xmpp_stanza_add_child(reply, query);
  xmpp_stanza_release(query);

  xmpp_send(conn, reply);
  xmpp_stanza_release(reply);
  return 1;
}

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

int message_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
  xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;
  xmpp_stanza_t *body, *reply;
  const char *type;
  char *intext, *replytext;
  int quit = 0;

  body = xmpp_stanza_get_child_by_name(stanza, "body");
  if (body == NULL) {
    return 1;
  }
  type = xmpp_stanza_get_type(stanza);
  if (type != NULL && strcmp(type, "error") == 0) {
    return 1;
  }

  intext = xmpp_stanza_get_text(body);

  printf("Incoming message from %s: %s\n", xmpp_stanza_get_from(stanza), intext);

  reply = xmpp_stanza_reply(stanza);
  if (xmpp_stanza_get_type(reply) == NULL) {
    xmpp_stanza_set_type(reply, "chat");
  }

  if (strcmp(intext, "quit") == 0) {
    replytext = strdup("bye!");
    quit = 1;
  } else {
    replytext = (char *) malloc(strlen(" to you too!") + strlen(intext) + 1);
    strcpy(replytext, intext);
    strcat(replytext, " to you too!");
  }
  xmpp_free(ctx, intext);
  xmpp_message_set_body(reply, replytext);

  xmpp_send(conn, reply);
  xmpp_stanza_release(reply);
  free(replytext);

  if (quit) {
    xmpp_disconnect(conn);
  }

  return 1;
}

/* define a handler for connection events */
void conn_handler(xmpp_conn_t * const conn, const xmpp_conn_event_t status,
  const int error, xmpp_stream_error_t * const stream_error,
  void * const userdata)
{
  xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;

  if (status == XMPP_CONN_CONNECT) {
    xmpp_stanza_t* pres;
    fprintf(stderr, "DEBUG: connected\n");
    xmpp_handler_add(conn, version_handler, "jabber:iq:version", "iq", NULL, ctx);
    xmpp_handler_add(conn, message_handler, NULL, "message", NULL, ctx);

    /* Send initial <presence/> so that we appear online to contacts */
    pres = xmpp_presence_new(ctx);
    xmpp_send(conn, pres);
    xmpp_stanza_release(pres);
  } else {
    fprintf(stderr, "DEBUG: disconnected\n");
    xmpp_stop(ctx);
  }
}

int main(int argc, char **argv)
{
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
    fprintf(stderr, "This version of the program requires one login.\n");
    close_config();
    exit(1);
  }
  struct config_settings *loginPtr = logins[0];
  struct config_settings login = *loginPtr;

  xmpp_ctx_t *ctx;
  xmpp_conn_t *conn;
  xmpp_log_t *log;
  const char *jid = login.jid;
  const char *pass = login.pass;
  const char *host = login.host;

  /* init library */
  xmpp_initialize();

  /* create a context */
  log = verbose == 1 ? xmpp_get_default_logger(XMPP_LEVEL_DEBUG) : xmpp_get_default_logger(XMPP_LEVEL_INFO); /* pass NULL instead to silence output */

  ctx = xmpp_ctx_new(NULL, log);

  /* create a connection */
  conn = xmpp_conn_new(ctx);

  xmpp_conn_set_flags(conn, login.flags);

  /* setup authentication information */
  xmpp_conn_set_jid(conn, jid);
  xmpp_conn_set_pass(conn, pass);

  /* initiate connection */
  xmpp_connect_client(conn, host, 0, conn_handler, ctx);

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
  xmpp_ctx_free(ctx);

  /* cleanup OpenSSL (must do for every thread) */
  ERR_remove_state(0);

  /* final shutdown of the library */
  xmpp_shutdown();

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
      {"config", required_argument, 0, 1001},
      {"verbose", no_argument, 0, 'v'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}
    };

    int option_index = 0;
    c = getopt_long(argc, argv, "hv", long_options, &option_index);
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
      case 'h':
        printf("Usage: %s [options]\n", argv[0]);
        printf("Options:\n");
        printf("  --config <file>\n");
        printf("    Path to configuration file.\n");
        printf("  --verbose\n");
        printf("    Use DEBUG level of libstrophe logging.\n");
        printf("  --help\n");
        printf("    Display this information.\n");
        exit(0);
        break;
      case 'v':
        verbose = 1;
        break;
      default:
        fprintf(stderr, "Command options fall through.\n");
        abort();
    }
  }
}

void open_config()
{
  if (strlen(CONFIG_FILE) == 0)
  {
    fprintf(stderr, "No configuration file specified.\n");
    exit(1);
  }

  config = &conf;
  config_init(config);

  int loaded_config = config_read_file(config, CONFIG_FILE);
  if (loaded_config != 1)
  {
    fprintf(stderr, "Error reading config file %s. Error on line %d: %s\n", config_error_file(config), config_error_line(config), config_error_text(config));
    config_destroy(config);
  }
}

void close_config()
{
  // Cleanup before config_destroy()
  for (int i = 0; i < logins_count; i++)
  {
    struct config_settings *loginPtr = logins[i];
    free(loginPtr);
  }
  config_destroy(config);
}

void servers_iterate(struct config_settings *logins[], int *logins_count, int max_logins)
{
  /* Loop through servers */
  struct config_setting_t conf_servers;
  struct config_setting_t *config_servers = &conf_servers;
  int server_count = get_root_element_count(config, "servers", config_servers);
  #ifdef BE_VERBOSE
  printf("Number of servers: %d\n", server_count);
  #endif

  for (int i = 0; i < server_count; i++)
  {
    struct config_setting_t *server_element = config_setting_get_elem(config_servers, i);
    if (server_element == NULL)
    {
      continue;
    }
    struct config_settings server_login = {0};
    server_login.pointer = server_element;

    struct config_setting_t *server_setting = NULL;

    int server_enabled = get_config_bool(server_element, "enabled");
    if (server_enabled == 0)
    {
      fprintf(stdout, "Server %d is not enabled.\n", i);
      continue;
    }
    else if (server_enabled > 0)
    {
      server_login.enabled = server_enabled;
      server_login.host = get_config_string(server_element, "host");
      const char *server_tls = get_config_string(server_element, "tls");
      server_login.flags = get_tls_flags(server_tls);

      #ifdef BE_VERBOSE
      printf("servers[%d].enabled = %d\n", i, server_login.enabled);
      printf("servers[%d].host = %s\n", i, server_login.host);
      printf("servers[%d].flags = %d\n", i, (int) server_login.flags);
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
  if (conf_logins == NULL)
  {
    fprintf(stdout, "No logins defined for server %d.\n", serverNumber);
  }
  int login_count = config_setting_length(conf_logins);
  #ifdef BE_VERBOSE
  printf("Number of logins for server %d: %d\n", serverNumber, login_count);
  #endif

  for (int i = 0; i < login_count; i++)
  {
    struct config_setting_t *login_element = config_setting_get_elem(conf_logins, i);
    if (login_element == NULL)
    {
      continue;
    }

    struct config_settings *loginPtr = NULL;
    loginPtr = (struct config_settings *) malloc(sizeof(struct config_settings));
    #ifdef BE_VERBOSE
    printf("Pointer loginPtr: %p\n", loginPtr);
    #endif
    memcpy(loginPtr, &server_login, sizeof(struct config_settings));
    loginPtr->pointer = login_element;
    loginPtr->jid = get_config_string(login_element, "jid");
    loginPtr->pass = get_config_string(login_element, "pass");

    #ifdef BE_VERBOSE
    printf("servers[%d].logins[%d].jid length = %d\n", serverNumber, i, (int) strlen(loginPtr->jid));
    printf("servers[%d].logins[%d].pass length = %d\n", serverNumber, i, (int) strlen(loginPtr->pass));
    printf("servers[%d].logins[%d].pointer = %p\n", serverNumber, i, loginPtr->pointer);
    #endif

    if (logins_count < max_logins)
    {
      logins[logins_count] = loginPtr;
      logins_count++;
    }
    else
    {
      fprintf(stderr, "Compiled with only %d maximum logins, configuration file contains at least %d.\n", max_logins, logins_count+1);
      fprintf(stderr, "Please modify 'int max_logins = %d' in source code and recompile.\n", max_logins);
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
    fprintf(stderr, "No %s found in configuration file.\n", name);
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
    fprintf(stderr, "No %s found in configuration file for this account.\n", name);
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
  printf("tls: %s\n", tls);
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
