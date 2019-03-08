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
/* libjson-c */
#include <json-c/json.h>
/* firebase-upstream-server */
#include "common.h"

/* Share variables between a pair of connection threads  */
struct connection_pair
{
  unsigned short thread_draining[2];
  int thread_return[2];
  pthread_t *thread[2];
  xmpp_conn_t *connections[2];
  xmpp_ctx_t *ctx[2];
  struct login_settings *login;
  xmpp_log_t *log;
  pthread_mutex_t *mutex[2];
  pthread_cond_t *draining[2];
};

/* Map a thread to a connection_pair* and its location in a connection_pair->thread[] */
struct threadmap
{
  unsigned short reconnect_delay;
  /* threadmap->loc is location in arrays in threadmap->my_pair */
  unsigned int loc;
  /* threadmap->id is location in all_threads[] array */
  unsigned int id;
  pthread_t thread;
  struct connection_pair *my_pair;
};


int command_options(int argc, char **argv);

void handle_sigint();

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

/* Command line variables */
char *CONFIG_FILE = "";
char LINE_TERMINATOR = '\n';
int use_record_separator = 0;
int use_length_prefix = 0;
int use_concat_output = 0;
int verbose = 0;
/* Variable to indicate user-initiated exit */
unsigned short shutting_down = 0;

/* Array of threadmaps */
struct threadmap *all_threads;
unsigned int thread_count = 0;

/* Change connection draining status of a thread/connection */
void connection_draining(struct threadmap *my_threadmap, int is_draining) {
  pthread_mutex_lock(my_threadmap->my_pair->mutex[my_threadmap->loc]);
  my_threadmap->my_pair->thread_draining[my_threadmap->loc] = is_draining;
  pthread_cond_signal(my_threadmap->my_pair->draining[my_threadmap->loc]);
  pthread_mutex_unlock(my_threadmap->my_pair->mutex[my_threadmap->loc]);
}

/* Print JSON object, formatted according to command line parameters */
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

/* Send an "ack" message back to the FCM Cloud Connection Server (CCS) */
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

/* Handle Firebase Cloud Messaging upstream messages from Cloud Connection Server */
int fcm_upstream_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const ptr)
{
  struct threadmap *my_threadmap = (struct threadmap *) ptr;
  xmpp_ctx_t *ctx = my_threadmap->my_pair->ctx[my_threadmap->loc];
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
        connection_draining(my_threadmap, 1);
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
  void * const ptr)
{
  struct threadmap *my_threadmap = (struct threadmap *) ptr;
  xmpp_ctx_t *ctx = my_threadmap->my_pair->ctx[my_threadmap->loc];
  int reconnect_status = -1;

  /* We're connected */
  if (status == XMPP_CONN_CONNECT) {
    fprintf(stderr, "DEBUG: CONNECTED\n");
    my_threadmap->reconnect_delay = 1;
    return;
  }
  /* We're not connected */
  fprintf(stderr, "DEBUG: DISCONNECTED\n");

  while (reconnect_status != 0) {
    /* Are we shutting down or connection draining? */
    if (shutting_down == 1 || my_threadmap->my_pair->thread_draining[my_threadmap->loc] == 1) {
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
    reconnect_status = xmpp_connect_client(conn, my_threadmap->my_pair->login->host, my_threadmap->my_pair->login->port, conn_handler, my_threadmap);
  }
}

/* Cleanup thread's OpenSSL and XMPP state */
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
  /* Free connection */
  xmpp_conn_release(my_threadmap->my_pair->connections[my_threadmap->loc]);
}

/* Function that blocks a thread until its counterpart is connection draining */
void swap_thread(struct threadmap *my_threadmap, int other_thread) {
  #ifdef BE_VERBOSE
  /* Check all threads use same instance of struct */
  printf("my_pair has pointer %p\n", (void *) my_threadmap->my_pair);
  /* Wait until other thread is connection draining */
  printf("I am %u, waiting for %d to change status.\n", my_threadmap->loc, other_thread);
  #endif
  while (my_threadmap->my_pair->thread_draining[other_thread] == 0) {
    pthread_cond_wait(my_threadmap->my_pair->draining[other_thread], my_threadmap->my_pair->mutex[other_thread]);
  }
  /* Do stuff needed here, but we're not using mutex for write lock, just waiting for value change */
  pthread_mutex_unlock(my_threadmap->my_pair->mutex[other_thread]);
  /* Do stuff that doesn't need a read/write lock here */
  /* Other connection is draining, we need to connect */
  #ifdef BE_VERBOSE
  printf("I am %u, %d has changed to connection draining.\n", my_threadmap->loc, other_thread);
  #endif
  xmpp_connect_client(my_threadmap->my_pair->connections[my_threadmap->loc], my_threadmap->my_pair->login->host, my_threadmap->my_pair->login->port, conn_handler, my_threadmap);
  xmpp_run(my_threadmap->my_pair->ctx[my_threadmap->loc]);
  #ifdef BE_VERBOSE
  printf("I am %u (%lu)... disconnected.\n", my_threadmap->loc, my_threadmap->thread);
  #endif
  /* Repeat forever */
  pthread_cleanup_push(thread_cleanup, my_threadmap);
  swap_thread(my_threadmap, other_thread);
  pthread_cleanup_pop(1);
}

/* Create one XMPP connection */
void *create_connection(void * ptr)
{
  /* Convert void* to struct */
  struct threadmap *my_threadmap = (struct threadmap *) ptr;
  struct connection_pair *my_pair = my_threadmap->my_pair;
  struct login_settings *login = my_pair->login;
  int other_thread;
  xmpp_conn_t *conn;

  /* create a connection */
  conn = xmpp_conn_new(my_pair->ctx[my_threadmap->loc]);
  /* store pointer to connection in array */
  my_pair->connections[my_threadmap->loc] = conn;
  /* set TLS connection flags */
  xmpp_conn_set_flags(conn, login->flags);

  /* setup authentication information */
  xmpp_conn_set_jid(conn, login->jid);
  xmpp_conn_set_pass(conn, login->pass);

  xmpp_handler_add(conn, fcm_upstream_handler, "google:mobile:data", "message", NULL, my_threadmap);

  my_pair->thread[my_threadmap->loc] = &my_threadmap->thread;
  /* The other thread in this connection pair isn't this thread */
  if (my_threadmap->loc == 0) {
    other_thread = 1;
  } else if (my_threadmap->loc == 1) {
    other_thread = 0;
  }

  /* On first run, only the primary thread should make a connection */
  if (my_threadmap->loc == 0)
  {
    /* initiate connection */
    xmpp_connect_client(conn, login->host, login->port, conn_handler, my_threadmap);
    /* enter the event loop -
    our connect handler will trigger an exit */
    xmpp_run(my_pair->ctx[my_threadmap->loc]);
    /* This thread is disconnected */
    /* fcm_upstream_handler should've fired up other thread if draining*/
    /* conn_handler should've attempted to reconnect indefinitely */
  }
  /* The secondary thread should wait until primary thread connection drains */
  /* A disconnected primary thread should wait until secondary thread drains */
  if (shutting_down != 1)
  {
    pthread_cleanup_push(thread_cleanup, my_threadmap);
    swap_thread(my_threadmap, other_thread);
    pthread_cleanup_pop(1);
  }
  /* On shutdown, cleanup primary threads that have never connection drained */
  thread_cleanup(my_threadmap);

  return NULL;
}

/* Create a pair of connection threads */
int create_connection_pair(struct connection_pair *my_pair, int first_thread)
{
  int i;
  for (i = 0; i < 2; i++) {
    struct threadmap *my_threadmap = &all_threads[first_thread + i];
    my_threadmap->id = first_thread + i;
    my_threadmap->loc = i;
    my_threadmap->reconnect_delay = 1;
    my_threadmap->my_pair = my_pair;
    my_threadmap->my_pair->mutex[i] = malloc(sizeof(pthread_mutex_t));
    my_threadmap->my_pair->draining[i] = malloc(sizeof(pthread_cond_t));
    if (my_threadmap->my_pair->mutex[i] == NULL || my_threadmap->my_pair->draining[i] == NULL) {
      fprintf(stderr, "create_connection_pair[%d].[%d]: Unable to allocate memory.\n", first_thread, i);
      return -1;
    }
    pthread_mutex_init(my_threadmap->my_pair->mutex[i], NULL);
    pthread_cond_init(my_threadmap->my_pair->draining[i], NULL);
    my_threadmap->my_pair->thread_draining[i] = 0;
    my_threadmap->my_pair->ctx[i] = xmpp_ctx_new(NULL, my_threadmap->my_pair->log);
    my_threadmap->my_pair->thread_return[i] = pthread_create(&my_threadmap->thread, NULL, &create_connection, (void *) my_threadmap);
    thread_count++;
  }
  return 0;
}

/* Get memory allocation for all_threads[] - 2 (struct threadmap) per login */
void threads_init(struct config_pointer *configPtr)
{
  all_threads = malloc(configPtr->login_count * 2 * sizeof(struct threadmap));
  if (all_threads == NULL) {
    fprintf(stderr, "threads_init: Unable to allocate memory.\n");
    close_config(configPtr);
    exit(1);
  }
}

/* Free connection pairs */
void threads_cleanup(unsigned int logins_count)
{
  unsigned int i;
  /* Release connection pairs (connection_pair*) */
  for (i = 0; i < thread_count; i++) {
    pthread_cond_destroy(all_threads[i].my_pair->draining[all_threads[i].loc]);
    pthread_mutex_destroy(all_threads[i].my_pair->mutex[all_threads[i].loc]);
    free(all_threads[i].my_pair->draining[all_threads[i].loc]);
    free(all_threads[i].my_pair->mutex[all_threads[i].loc]);
  }
  for (i = 0; i < logins_count; i++) {
    free(all_threads[i*2].my_pair);
  }
  /* release *all_threads */
  free(all_threads);
}

/* Start libstrophe library and create connection threads (blocking) */
void connections_start(struct login_settings *logins, unsigned int logins_count)
{
  xmpp_log_t *log;
  unsigned int i;
  /* init libstrophe library */
  xmpp_initialize();

  /* Set libstrophe log level for all connections */
  /* TODO: Make verbosity level configurable */
  log = verbose == 1 ? xmpp_get_default_logger(XMPP_LEVEL_DEBUG) : xmpp_get_default_logger(XMPP_LEVEL_INFO); /* pass NULL instead to silence output */

  for (i = 0; i < logins_count; i++) {
    struct connection_pair *new_pair;
    struct login_settings *login;
    new_pair = (struct connection_pair *) (malloc(sizeof(struct connection_pair) * 1));
    if (new_pair == NULL) {
      fprintf(stderr, "connections_start[%u]: Unable to allocate memory.\n", i);
      return;
    }

    login = &logins[i];
    new_pair->login = login;
    new_pair->log = log;

    logins[i].pairs = new_pair;
    if (create_connection_pair(new_pair, i) == -1) {
      return;
    }
  }
}

/* Join threads and shutdown libstrophe library */
void connections_cleanup()
{
  unsigned int i;
  for (i = 0; i < thread_count; i++) {
    pthread_join(all_threads[i].thread, NULL);
    /* Release connection context */
    xmpp_ctx_free(all_threads[i].my_pair->ctx[all_threads[i].loc]);
  }
  /* final shutdown of the libstrophe library */
  xmpp_shutdown();
}

/* Run the program (blocking) */
void main_run() {
  struct login_settings *logins;
  struct config_pointer *configPtr;
  struct config_pointer newConfigPtr;
  /* Create a temporary pointer for logins[] */
  logins = (struct login_settings *) calloc(0, sizeof(struct login_settings));
  if (logins == NULL) {
    fprintf(stderr, "main: Unable to allocate memory.\n");
    exit(1);
  }
  /* Open configuration file and populate logins[] */
  configPtr = &newConfigPtr;
  configPtr = open_config(CONFIG_FILE, &logins, configPtr);
  if (configPtr->pointer == NULL || configPtr->login_count < 1) {
    free(logins);
    exit(1);
  }
  /* Get memory allocation for all_threads[] - 2 (struct threadmap) per login */
  threads_init(configPtr);
  /* Start libstrophe library and create connection threads (blocking) */
  connections_start(logins, configPtr->login_count);
  /* Join threads and shutdown libstrophe library (program is closing) */
  connections_cleanup();
  /* Free all_threads[] */
  threads_cleanup(configPtr->login_count);
  /* Free logins[] */
  free(logins);
  /* Close config file */
  close_config(configPtr);
}

int main(int argc, char **argv) {
  /* Ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);
  /* Close connections on SIGINT */
  signal(SIGINT, handle_sigint);
  /* Set verbosity level if compiled with BE_VERBOSE defined */
  #ifdef BE_VERBOSE
  verbose = 1;
  #endif
  /* Parse command line arguments */
  command_options(argc, argv);
  /* Run the program (blocking) */
  main_run();
  /* Exit */
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

/*
* Handle SIGINT signal - rely on xmpp_run() returning after connections closed
*/
void handle_sigint()
{
  unsigned int i;
  shutting_down = 1;
  /* Disconnect connected threads. */
  for (i = 0; i < thread_count; i++) {
    int thread_id = all_threads[i].loc;
    xmpp_disconnect(all_threads[i].my_pair->connections[thread_id]);
  }
  /* Give time for disconnects. */
  sleep(3);
  /* End all connection threads. */
  /* Threads waiting for "pthread_cond_t draining" will call thread_cleanup() */
  for (i = 0; i < thread_count; i++) {
    pthread_cancel(all_threads[i].thread);
  }
}
