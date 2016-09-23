#ifndef BATTLEYE_RCON_H
#define BATTLEYE_RCON_H

#include "rcon.h"
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint8_t header[2];
    uint32_t crc;
    uint8_t endheader;
    uint8_t type;
    uint8_t *body;
} be_rcon_message_t;

typedef enum {
    be_rcon_type_auth = 0x00,
    be_rcon_type_command = 0x01,
    be_rcon_type_message = 0x02,
} be_rcon_type_t;

extern be_rcon_message_t *be_rcon_new(void);
extern void be_rcon_free(be_rcon_message_t *msg);
extern void be_rcon_freev(be_rcon_message_t **msg);

extern int32_t be_rcon_protocol(void);

extern rcon_error_t be_rcon_serialize(be_rcon_message_t const *msg,
                                      uint8_t **buf, size_t *sz);

extern be_rcon_message_t *be_rcon_auth(char const *password);
extern be_rcon_message_t *be_rcon_command(char const *command);

extern char const *be_rcon_get_body(be_rcon_message_t const *msg);


#endif
