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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <strophe.h>


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

int message_handler(xmpp_conn_t * const conn, xmpp_stanza_t * const stanza, void * const userdata)
{
    xmpp_ctx_t *ctx = (xmpp_ctx_t*)userdata;
    xmpp_stanza_t *body, *reply;
    const char *type;
    char *intext, *replytext;
    int quit = 0;

    body = xmpp_stanza_get_child_by_name(stanza, "body");
    if (body == NULL)
        return 1;
    type = xmpp_stanza_get_type(stanza);
    if (type != NULL && strcmp(type, "error") == 0)
        return 1;

    intext = xmpp_stanza_get_text(body);

    printf("Incoming message from %s: %s\n", xmpp_stanza_get_from(stanza), intext);

    reply = xmpp_stanza_reply(stanza);
    if (xmpp_stanza_get_type(reply) == NULL)
        xmpp_stanza_set_type(reply, "chat");

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

    if (quit)
        xmpp_disconnect(conn);

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
    }
    else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(ctx);
    }
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    char *jid, *pass;

    /* take a jid and password on the command line */
    if (argc != 3) {
        fprintf(stderr, "Usage: bot <jid> <pass>\n\n");
        return 1;
    }

    jid = argv[1];
    pass = argv[2];

    /* init library */
    xmpp_initialize();

    /* create a context */
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG); /* pass NULL instead to silence output */
    ctx = xmpp_ctx_new(NULL, log);

    /* create a connection */
    conn = xmpp_conn_new(ctx);

    /*
     * also you can disable TLS support or force legacy SSL
     * connection without STARTTLS
     *
     * see xmpp_conn_set_flags() or examples/basic.c
     */

    /* setup authentication information */
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, ctx);

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
