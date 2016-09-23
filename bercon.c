#include "bercon.h"

#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>

be_rcon_message_t *be_rcon_new(void)
{
    be_rcon_message_t *tmp = NULL;

    tmp = calloc(1, sizeof(be_rcon_message_t));
    if (tmp == NULL) {
        return tmp;
    }

    tmp->header[0] = 'B';
    tmp->header[1] = 'E';
    tmp->endheader = 0xFF;

    return tmp;
}

void be_rcon_free(be_rcon_message_t *msg)
{
    if (msg == NULL) {
        return;
    }

    free(msg->body);
    free(msg);
}

void be_rcon_freev(be_rcon_message_t **m)
{
    be_rcon_message_t **i = NULL;

    return_if_true(m == NULL,);

    for (i = m; *i != NULL; i++) {
        be_rcon_free(*i);
    }

    free(m);
}

extern int32_t be_rcon_protocol(void)
{
    /* BErcon does UDP
     */
    return SOCK_DGRAM;
}

static void be_rcon_update_crc(be_rcon_message_t *msg)
{
    uint32_t crc = 0;

    crc = crc32(0L, NULL, 0);

    crc = crc32(crc, &msg->type, sizeof(uint8_t));
    crc = crc32(crc, msg->body, strlen((char *)msg->body));

    msg->crc = crc;
}

be_rcon_message_t * be_rcon_auth(char const *password)
{
    be_rcon_message_t *msg = NULL;

    msg = be_rcon_new();
    if (msg == NULL) {
        return msg;
    }

    msg->type = be_rcon_type_auth;
    msg->body = (uint8_t*)strdup(password);
    be_rcon_update_crc(msg);

    return msg;
}

be_rcon_message_t * be_rcon_command(char const *command)
{
    be_rcon_message_t *msg = NULL;

    msg = be_rcon_new();
    if (msg == NULL) {
        return msg;
    }

    msg->type = be_rcon_type_command;
    msg->body = (uint8_t*)strdup(command);
    be_rcon_update_crc(msg);

    return msg;
}

char const *be_rcon_get_body(be_rcon_message_t const *msg)
{
    return (char const *)msg->body;
}

rcon_error_t
be_rcon_serialize(be_rcon_message_t const *msg, uint8_t **buf, size_t *sz)
{
    uint8_t *b = NULL;
    size_t s;
    FILE *str;

    return_if_true(msg == NULL, rcon_error_args);

    str = open_memstream((char**)&b, &s);
    if (str == NULL) {
        return rcon_error_memory;
    }

    /* Header: 'B' 'E' CRC32 0xFF
     */
    fwrite(msg->header, 2, sizeof(uint8_t), str);
    fwrite(&msg->crc, 1, sizeof(msg->crc), str);
    fwrite(&msg->endheader, 1, sizeof(msg->endheader), str);

    /* Now comes type
     */
    fwrite(&msg->type, 1, sizeof(msg->type), str);

    /* And body (without null terminator
     */
    if (msg->body != NULL) {
        fwrite(msg->body, strlen((char const*)msg->body), sizeof(uint8_t), str);
    }

    fflush(str);
    fclose(str);

    *buf = b;
    *sz = s;

    return rcon_error_success;
}
