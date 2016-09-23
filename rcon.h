#ifndef RCON_H
#define RCON_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

#define return_if_true(a,v) do { if (a) return v; } while(0)

typedef enum {
    rcon_error_success = 0,
    rcon_error_moredata,
    rcon_error_authinvalid,
    rcon_error_unspecified,
    rcon_error_protocolerror,
    rcon_error_memory,
    rcon_error_args,
} rcon_error_t;

extern uint32_t crc32(uint32_t crc, uint8_t const *buf, uint32_t len);

typedef int32_t (*rcon_proto_protocol)(void);
typedef void *  (*rcon_proto_auth)(char const *password);
typedef void *  (*rcon_proto_command)(char const *command);
typedef rcon_error_t (*rcon_proto_command_wait)(void const *m, void ***replies,
                                                size_t *off, void const *buf,
                                                size_t size);
typedef rcon_error_t (*rcon_proto_serialize)(void const *m, uint8_t **buf,
                                             size_t *sz);
typedef rcon_error_t (*rcon_proto_auth_wait)(void const *auth,
                                             size_t *off,
                                             void const *buf, size_t sz);

typedef char const * (*rcon_proto_get_body)(void const *m);

typedef void (*rcon_proto_free)(void *);
typedef void (*rcon_proto_freev)(void **);

typedef struct {
    char *name;
    char *shortname;

    rcon_proto_protocol protocol;
    rcon_proto_auth auth;
    rcon_proto_auth_wait auth_wait;
    rcon_proto_command command;
    rcon_proto_command_wait command_wait;
    rcon_proto_serialize serialize;
    rcon_proto_get_body get_body;
    rcon_proto_free free;
    rcon_proto_freev freev;
} rcon_proto_t;

extern rcon_proto_t protocols[];

extern rcon_proto_t *rcon_proto_by_name(char const *name);
extern rcon_proto_t *rcon_proto_default(void);

#endif
