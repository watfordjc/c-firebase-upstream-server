/* Standard Libraries */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
/* libconfig */
#include <libconfig.h>
/* libstrophe */
#include <strophe.h>
/* firebase-upstream-server */
#include "common.h"

/* libconfig < v1.5 - renamed function */
#if (LIBCONFIG_VER_MAJOR <= 1) && (LIBCONFIG_VER_MINOR <= 4)
#define config_setting_lookup config_lookup_from
#endif

static int servers_iterate(struct config_t *config, struct login_settings **logins);
static int logins_iterate(struct config_setting_t *config_servers, struct login_settings *logins, int login_count);

static long get_tls_flags(const char *tls);
static unsigned short get_port(int port);

static int get_root_element_count(config_t *config, char *name, config_setting_t *config_element);
static int get_config_int(config_setting_t *setting, char *name);
static int get_config_bool(config_setting_t *setting, char *name);
static const char *get_config_string(config_setting_t *setting, char *name);


/* Open libconfig style configuration file located at 'file' */
/* The memory location of (struct login_settings) 'logins' will be changed
    after the number of logins in the configuration file is known. */
struct config_pointer *open_config(char *file, struct login_settings **logins, struct config_pointer *configPtr)
{
  int loaded_config, login_count;
  struct config_t *config;
  config = calloc(sizeof(config_t), 1);

  /* Initialise ligconfig configuration object - global variable */
  config_init(config);

  /* Set config_pointer->pointer to point at configuration object */
  configPtr->pointer = config;
  /* Read configuration file 'file' into memory location of X_CONFIG */
  loaded_config = config_read_file(config, file);
  if (loaded_config != 1)
  {
    fprintf(stderr, "conf: Error reading config file %s. Error on line %d: %s\n", config_error_file(config), config_error_line(config), config_error_text(config));
    config_destroy(config);
    configPtr->pointer = NULL;
    return configPtr;
  }

  /* Populate logins[] and get login_count by iterating through servers & logins */
  login_count = servers_iterate(config, logins);
  /* Set config_pointer->login_count to total number of logins */
  configPtr->login_count = login_count;

  /* Return (struct config_pointer *) containing configuration object pointer & number of logins */
  return configPtr;
}

void close_config(struct config_pointer *configPtr)
{
  /* Destroy ligconfig configuration object */
  config_destroy(configPtr->pointer);
  free(configPtr->pointer);
}


static int servers_iterate(struct config_t *config, struct login_settings **logins)
{
  struct config_setting_t config_servers;
  struct config_setting_t *server_element;
  struct login_settings *loginPtr;
  int i, server_count, login_count;
  short unsigned int *logins_per_server;

  /* Get from config the number of servers inside servers: block */
  server_count = get_root_element_count(config, "servers", &config_servers);
  /* Initialise login_count to zero */
  login_count = 0;
  /* Create an array of integers to store the number of logins for each server */
  logins_per_server = malloc(sizeof(short unsigned int) * server_count);
  if (logins_per_server == NULL) {
    fprintf(stderr, "conf: Unable to allocate memory.\n");
    return 0;
  }
  #ifdef BE_VERBOSE
  fprintf(stderr, "conf: Number of servers: %d\n", server_count);
  #endif

  /* Loop through servers */
  for (i = 0; i < server_count; i++)
  {
    int server_enabled;
    /* Get the i'th server */
    server_element = config_setting_get_elem(&config_servers, i);
    if (server_element == NULL)
    {
      logins_per_server[i] = 0;
      continue;
    }
    /* Check if server block is disabled */
    server_enabled = get_config_bool(server_element, "enabled");
    if (server_enabled == 0)
    {
      logins_per_server[i] = 0;
      fprintf(stderr, "conf: Server %d is not enabled.\n", i);
      continue;
    }
    else if (server_enabled > 0)
    {
      /* Get from i'th server block the logins:{} block */
      struct config_setting_t *conf_logins = config_setting_lookup(server_element, "logins");
      if (conf_logins == NULL)
      {
        logins_per_server[i] = 0;
        fprintf(stderr, "conf: No logins defined for server %d.\n", i);
        continue;
      }
      /* Get the number of logins for this server */
      logins_per_server[i] = config_setting_length(conf_logins);
      /* Increase logins_count by the number of logins for this server */
      login_count += logins_per_server[i];
      #ifdef BE_VERBOSE
      fprintf(stderr, "conf: Number of logins for server %d: %d\n", i, logins_per_server[i]);
      #endif
    }
  }
  /* logins_per_server[] has now been filled, and we know server_count & login_count */
  #ifdef BE_VERBOSE
  fprintf(stderr, "conf: Number of logins: %d\n", login_count);
  #endif
  /* If there aren't at least 1 login, return early */
  if (login_count < 1) {
    return 0;
  }
  /* Remember where *logins points to in case realloc fails */
  loginPtr = *logins;
  /* Increase the size of logins[] to one (struct login_settings) per login */
  *logins = (struct login_settings *) realloc(*logins, sizeof(struct login_settings) * login_count);
  /* Check that realloc() of *logins was successful and that **logins isn't NULL */
  if (*logins == NULL || *logins == loginPtr || logins == NULL) {
    fprintf(stderr, "conf: Unable to re-allocate memory.\n");
    return 0;
  }
  /* Set loginPtr to the start of the new memory location of logins[] */
  loginPtr = logins[0];

  /* Loop through servers a second time */
  for (i = 0; i < server_count; i++) {
    if (logins_per_server[i] == 0) {
      continue;
    }
    /* Get the i'th server */
    server_element = config_setting_get_elem(&config_servers, i);
    /* Loop through the logins for this server, and then */
    /* set loginPtr to the start of logins[loginPtr + logins_per_server[i]] */
    loginPtr += logins_iterate(server_element, loginPtr, logins_per_server[i]);
  }

  /* Free array of integers storing the number of logins for each server */
  free(logins_per_server);
  /* Return number of logins for all servers (size of logins[] array) */
  return login_count;
}

static int logins_iterate(struct config_setting_t *server_element, struct login_settings *logins, int login_count)
{
  int i;
  /* Get logins:{} block for server server_element */
  struct config_setting_t *conf_logins = config_setting_lookup(server_element, "logins");
  struct config_setting_t *login_element;
  for (i = 0; i < login_count; i++) {
    /* Get configuration file logins[i] for this server */
    login_element = config_setting_get_elem(conf_logins, i);
    /* Get memory location for (struct login_settings) for logins[i] */
    logins = &logins[i];
    /* Populate logins[i] for this login */
    logins->enabled = 1;
    logins->host = get_config_string(server_element, "host");
    logins->flags = get_tls_flags(get_config_string(server_element, "tls"));
    logins->port = get_port(get_config_int(server_element, "port"));
    logins->pointer = login_element;
    logins->jid = get_config_string(login_element, "jid");
    logins->pass = get_config_string(login_element, "pass");
    #ifdef BE_VERBOSE
    fprintf(stderr, "conf: logins[%d].enabled = %d\n", i, logins->enabled);
    fprintf(stderr, "conf: logins[%d].host = %s\n", i, logins->host);
    fprintf(stderr, "conf: logins[%d].port = %u\n", i, logins->port);
    fprintf(stderr, "conf: logins[%d].flags = %d\n", i, (int) logins->flags);
    fprintf(stderr, "conf: logins[%d].jid length = %lu\n", i, strlen(logins->jid));
    fprintf(stderr, "conf: logins[%d].pass length = %lu\n", i, strlen(logins->pass));
    fprintf(stderr, "conf: logins[%d].pointer = %p\n", i, (void *) logins->pointer);
    #endif
  }
  /* Return number of logins for this server as passed to method (for pointer math) */
  return login_count;
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
static int get_root_element_count(config_t *config, char *name, config_setting_t *config_element)
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
* Function get_config_int looks up the integer value of 'name'
*  in the configuration setting 'setting' and returns the integer.
* -1 is returned if 'name' does not exist.
*/
static int get_config_int(config_setting_t *setting, char *name)
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
static int get_config_bool(config_setting_t *setting, char *name)
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
static const char *get_config_string(config_setting_t *setting, char *name)
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
static long get_tls_flags(const char *tls)
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
  fprintf(stderr, "conf: tls setting for login: %s\n", tls);
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
static unsigned short get_port(int port)
{
  if (port <= 0 || port > 65535) {
    return 0;
  } else {
    return (unsigned short) port;
  }
}
