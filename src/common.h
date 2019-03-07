struct login_settings
{
  unsigned short port;
  int enabled;
  long flags;
  const char *host;
  const char *jid;
  const char *pass;
  struct config_setting_t *pointer;
  struct connection_pair *pairs;
};

struct config_pointer
{
  int login_count;
  struct config_t *pointer;
};

struct config_pointer *open_config(char *file, struct login_settings **config, struct config_pointer *configPtr);
void close_config(struct config_pointer *configPtr);
