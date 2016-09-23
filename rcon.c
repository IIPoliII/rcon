#include "rcon.h"

#include "srcrcon.h"
#include "bercon.h"

#include <string.h>

rcon_proto_t protocols[] =
{
    {
        "source",
        "src",
        src_rcon_protocol,
        (rcon_proto_auth)src_rcon_auth,
        (rcon_proto_auth_wait)src_rcon_auth_wait,
        (rcon_proto_command)src_rcon_command,
        (rcon_proto_command_wait)src_rcon_command_wait,
        (rcon_proto_serialize)src_rcon_serialize,
        (rcon_proto_get_body)src_rcon_get_body,
        (rcon_proto_free)src_rcon_free,
        (rcon_proto_freev)src_rcon_freev,
    },
    {
        "battleye",
        "be",
        be_rcon_protocol,
        (rcon_proto_auth)be_rcon_auth,
        NULL,
        (rcon_proto_command)be_rcon_command,
        NULL,
        (rcon_proto_serialize)be_rcon_serialize,
        (rcon_proto_get_body)be_rcon_get_body,
        (rcon_proto_free)be_rcon_free,
        (rcon_proto_freev)be_rcon_freev,
    },
    { NULL, NULL, NULL, NULL }
};

rcon_proto_t *rcon_proto_by_name(char const *name)
{
    uint32_t i = 0;

    for (; protocols[i].name != NULL; i++) {
        if (strcmp(protocols[i].name, name) == 0 ||
            strcmp(protocols[i].shortname, name) == 0) {
            return protocols+i;
        }
    }

    return NULL;
}

rcon_proto_t *rcon_proto_default(void)
{
    /* src rcon is default
     */
    return protocols;
}
