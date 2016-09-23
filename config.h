#ifndef RCON_CONFIG_H
#define RCON_CONFIG_H

#include "rcon.h"

extern void config_free(void);
extern int config_load(char const *file);

extern int config_host_data(char const *name, char **hostname,
                            char **port, char **passwd, rcon_proto_t **proto);

#endif
