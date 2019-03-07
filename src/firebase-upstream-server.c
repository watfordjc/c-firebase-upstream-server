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
#include <pthread.h>
#include <unistd.h>
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
struct config_settings *logins[MAX_LOGINS] = {0};



int logins_count = 0;
int thread_count = 0;

struct connection_pair
{
  int thread_draining[2];
  pthread_mutex_t mutex[2];
  pthread_cond_t draining[2];
  pthread_t *thread[2];
  int thread_return[2];
  xmpp_conn_t *connections[2];
  xmpp_ctx_t *ctx[2];
  struct config_settings *login;
  xmpp_log_t *log;
};

struct config_settings
{
  int enabled;
  const char *host;
  unsigned short port;
  long flags;
  const char *jid;
  const char *pass;
  struct config_setting_t *pointer;
  struct connection_pair *pairs;
};
struct config_t conf;
struct config_t *config;

/* Map threads to connection pairs and location in a connection_pair->thread[] */
struct threadmap
{
  unsigned short reconnect_delay;
  pthread_t thread;
  struct connection_pair *my_pair;
  int loc;
  int id;
};
/* Array of threadmaps */
struct threadmap *all_threads;

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
void ERR_remove_thread_state();

int verbose;
int shutting_down = 0;

void connection_draining(pthread_t thread, int is_draining) {
  int i;
  int thread_id, *thread_draining;
  struct connection_pair *my_pair;
  struct threadmap *my_threadmap;
  for (i = 0; i < thread_count; i++) {
    if (pthread_equal(all_threads[i].thread, thread)) {
      my_threadmap = &all_threads[i];
      my_pair = my_threadmap->my_pair;
      thread_id = my_threadmap->loc;
      pthread_mutex_lock(&my_pair->mutex[thread_id]);
      thread_draining = my_pair->thread_draining;
      thread_draining[thread_id] = is_draining;
      pthread_cond_signal(&my_pair->draining[thread_id]);
      pthread_mutex_unlock(&my_pair->mutex[thread_id]);
      break;
    }
  }
}

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
      /* If control type is CONNECTION_DRAINING, activate other thread */
      if (strcmp("CONNECTION_DRAINING", json_object_get_string(control_type)) == 0) {
        fprintf(stderr, "DEBUG: CONNECTION_DRAINING\n");
        /* This thread's connection is draining */
        connection_draining(pthread_self(), 1);
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
  int i;
  xmpp_ctx_t *ctx = (xmpp_ctx_t *)userdata;
  struct threadmap *my_threadmap;
  pthread_t thread;

  /* Get threadmap */
  thread = pthread_self();
  my_threadmap = NULL;
  for (i = 0; i < thread_count; i++) {
    if (pthread_equal(all_threads[i].thread, thread)) {
      my_threadmap = &all_threads[i];
    }
  }

  if (status == XMPP_CONN_CONNECT) {
    fprintf(stderr, "DEBUG: CONNECTED\n");
    my_threadmap->reconnect_delay = 1;
    return;
  }

  /* We're not connected */
  fprintf(stderr, "DEBUG: DISCONNECTED\n");
  /* Are we shutting down? */
  if (shutting_down == 1) {
    xmpp_stop(ctx);
    return;
  }


  /* Check if we're connection draining */
  if (my_threadmap == NULL || my_threadmap->my_pair->thread_draining[my_threadmap->loc] == 1) {
    xmpp_stop(ctx);
    return;
  }

  /* We're not connection draining, attempt reconnection */
  /* Double reconnect delay each attempt until delay is 128 seconds */
  if (my_threadmap->reconnect_delay < 128) {
    my_threadmap->reconnect_delay *= 2;
  }
  #ifdef BE_VERBOSE
  fprintf(stderr, "conn: Reconnect delay is %ds.\n", my_threadmap->reconnect_delay);
  #endif
  /* Wait for reconnect delay */
  sleep(my_threadmap->reconnect_delay);
  /* Attempt to reconnect */
  xmpp_connect_client(conn, my_threadmap->my_pair->login->host, my_threadmap->my_pair->login->port, conn_handler, userdata);
}

void thread_cleanup(void * ptr)
{
  struct threadmap *my_threadmap = (struct threadmap *) ptr;
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
  ERR_remove_thread_state(NULL);
  /* cleanup OpenSSL (must do for every thread) */
  ERR_remove_state(0);

  xmpp_conn_release(my_threadmap->my_pair->connections[my_threadmap->loc]);
}

void swap_thread(struct threadmap *my_threadmap, struct connection_pair *my_pair, pthread_t *tid, int thread_id, int other_thread) {
  #ifdef BE_VERBOSE
  /* Check all threads use same instance of struct */
  printf("my_pair has pointer %p\n", (void *) my_pair);
  /* Wait until other thread is connection draining */
  printf("I am %d, waiting for %d to change status.\n", thread_id, other_thread);
  #endif
  while (my_pair->thread_draining[other_thread] == 0) {
    pthread_cond_wait(&my_pair->draining[other_thread], &my_pair->mutex[other_thread]);
  }
  /* Do stuff needed here, but we're not using mutex for write lock, just waiting for value change */
  pthread_mutex_unlock(&my_pair->mutex[other_thread]);
  /* Do stuff that doesn't need a read/write lock here */
  /* Other connection is draining, we need to connect */
  #ifdef BE_VERBOSE
  printf("I am %d, %d has changed to connection draining.\n", thread_id, other_thread);
  #endif
  xmpp_connect_client(my_pair->connections[thread_id], my_pair->login->host, my_pair->login->port, conn_handler, my_pair->ctx[thread_id]);
  xmpp_run(my_pair->ctx[thread_id]);
  #ifdef BE_VERBOSE
  printf("I am %d (%lu)... disconnected.\n", thread_id, *tid);
  #endif
  /* Repeat forever */
  pthread_cleanup_push(thread_cleanup, my_threadmap);
  swap_thread(my_threadmap, my_pair, tid, thread_id, other_thread);
  pthread_cleanup_pop(1);
}

void *create_connection(void * ptr)
{
  /* Convert void* to struct */
  struct threadmap *my_threadmap = (struct threadmap *) ptr;
  struct connection_pair *my_pair = my_threadmap->my_pair;
  struct config_settings *login = my_pair->login;
  int thread_id = my_threadmap->loc;
  int other_thread;
  pthread_t tid;
  xmpp_conn_t *conn;

  /* create a connection */
  conn = xmpp_conn_new(my_pair->ctx[thread_id]);
  /* store pointer to connection in array */
  my_pair->connections[thread_id] = conn;
  /* set TLS connection flags */
  xmpp_conn_set_flags(conn, login->flags);

  /* setup authentication information */
  xmpp_conn_set_jid(conn, login->jid);
  xmpp_conn_set_pass(conn, login->pass);

  xmpp_handler_add(conn, fcm_upstream_handler, "google:mobile:data", "message", NULL, my_pair->ctx[thread_id]);

  /* Get thread ID so it can be compared */
  tid = pthread_self();
  my_pair->thread[my_threadmap->loc] = &my_threadmap->thread;
  /* The other thread in this connection pair isn't this thread */
  if (thread_id == 0) {
    other_thread = 1;
  } else if (thread_id == 1) {
    other_thread = 0;
  }

  /* On first run, only the primary thread should make a connection */
  if (thread_id == 0)
  {
    /* initiate connection */
    xmpp_connect_client(conn, login->host, login->port, conn_handler, my_pair->ctx[thread_id]);
    /* enter the event loop -
    our connect handler will trigger an exit */
    xmpp_run(my_pair->ctx[thread_id]);
    /* This thread is disconnected */
    /* fcm_upstream_handler should've fired up other thread if draining*/
    /* conn_handler should've attempted to reconnect indefinitely */
  }
  /* The secondary thread should wait until primary thread connection drains */
  /* A disconnected primary thread should wait until secondary thread drains */
  if (shutting_down != 1)
  {
    pthread_cleanup_push(thread_cleanup, my_threadmap);
    swap_thread(my_threadmap, my_pair, &tid, thread_id, other_thread);
    pthread_cleanup_pop(1);
  }

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
  ERR_remove_thread_state(NULL);
  /* cleanup OpenSSL (must do for every thread) */
  ERR_remove_state(0);

  /* release our connection */
  xmpp_conn_release(conn);

  return NULL;
}

void create_connection_pair(struct connection_pair *my_pair, int first_thread)
{
  int i;
  for (i = 0; i < 2; i++) {
    pthread_mutex_init(&my_pair->mutex[i], NULL);
    pthread_cond_init(&my_pair->draining[i], NULL);
    my_pair->thread_draining[i] = 0;
  }
  for (i = 0; i < 2; i++) {
    struct threadmap *my_threadmap = &all_threads[first_thread + i];
    my_threadmap->my_pair = my_pair;
    my_threadmap->loc = i;
    my_pair->ctx[i] = xmpp_ctx_new(NULL, my_pair->log);
    my_pair->thread_return[i] = pthread_create(&my_threadmap->thread, NULL, &create_connection, (void *) my_threadmap);
    thread_count++;
  }
}

void join_all_threads()
{
  int i;
  for (i = 0; i < thread_count; i++) {
      pthread_join(all_threads[i].thread, NULL);
  }
}

int main(int argc, char **argv)
{
  xmpp_log_t *log;
  int i;

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
  all_threads = malloc(logins_count * 2 * sizeof(struct threadmap));
  if (all_threads == NULL) {
    fprintf(stderr, "conf: Unable to allocate memory.");
    close_config();
    exit(1);
  }


  if (logins_count != 1)
  {
    fprintf(stderr, "conf: This version of the program requires one login.\n");
    close_config();
    exit(1);
  }

  /* init library */
  xmpp_initialize();

  /* create a context */
  log = verbose == 1 ? xmpp_get_default_logger(XMPP_LEVEL_DEBUG) : xmpp_get_default_logger(XMPP_LEVEL_INFO); /* pass NULL instead to silence output */

  for (i = 0; i < logins_count; i++) {
    struct connection_pair *new_pair;
    struct config_settings *login;
    new_pair = (struct connection_pair *) (malloc(sizeof(struct connection_pair) * 1));

    login = logins[i];
    new_pair->login = login;
    new_pair->log = log;

    logins[i]->pairs = new_pair;

    all_threads[i].my_pair = new_pair;
    all_threads[i+1].my_pair = new_pair;
    all_threads[i].id = i;
    all_threads[i+1].id = i + 1;
    all_threads[i].loc = 0;
    all_threads[i+1].loc = 1;
    all_threads[i].reconnect_delay = 1;
    all_threads[i+1].reconnect_delay = 1;
    create_connection_pair(new_pair, i);
  }

  for (i = 0; i < thread_count; i++) {
    pthread_join(all_threads[i].thread, NULL);
    /* Release our context */
    /* Release connection context */
    xmpp_ctx_free(all_threads[i].my_pair->ctx[all_threads[i].loc]);
  }

  /* final shutdown of the library */
  xmpp_shutdown();

  /* Release connection pairs (connection_pair*) */
  for (i = 0; i < logins_count; i++) {
    free(all_threads[i*2].my_pair);
  }

  /* release *all_threads */
  free(all_threads);

  /* close config file */
  close_config();

  return 0;
}

void print_command_options_help(char *argv0, int exit_code)
{
  fprintf(stderr, "Usage: %s [options]\n", argv0);
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
  exit(exit_code);
}

/* Parse command line arguments */
int command_options(int argc, char **argv)
{
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
    if (c == -1) {
      break;
    }

    switch (c)
    {
      case 0:
        /* if this options, set a flag, do nothing else now */
        if (long_options[option_index].flag != 0) {
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
        print_command_options_help(argv[0], 0);
        break;
      default:
        print_command_options_help(argv[0], 1);
        break;
    }
  }
  if (strcmp(CONFIG_FILE, "") == 0) {
    fprintf(stderr, "No configuration file specified.\n");
    print_command_options_help(argv[0], 1);
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
    if (loginPtr == NULL) {
      fprintf(stderr, "conf: Unable to allocate memory.");
      exit(1);
    }
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
  shutting_down = 1;
  /* Disconnect connected threads. */
  for (i = 0; i < thread_count; i++) {
    int thread_id = all_threads[i].loc;
    xmpp_disconnect(all_threads[i].my_pair->connections[thread_id]);
  }
  /* Give time for disconnects. */
  sleep(1);
  /* End all connection threads. */
  /* Threads waiting for "pthread_cond_t draining" will call thread_cleanup() */
  for (i = 0; i < thread_count; i++) {
    pthread_cancel(all_threads[i].thread);
  }
}
