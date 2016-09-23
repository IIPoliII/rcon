#include "rcon.h"
#include "srcrcon.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <sys/types.h>
#include <sys/socket.h>

static void src_rcon_update_size(src_rcon_message_t *m);
static void src_rcon_random_id(src_rcon_message_t *m);

void src_rcon_free(src_rcon_message_t *msg)
{
    return_if_true(msg == NULL,);

    free(msg->body);
    free(msg);
}

void src_rcon_freev(src_rcon_message_t **m)
{
    src_rcon_message_t **i = NULL;

    return_if_true(m == NULL,);

    for (i = m; *i != NULL; i++) {
        src_rcon_free(*i);
    }

    free(m);
}

src_rcon_message_t *src_rcon_new(void)
{
    src_rcon_message_t *tmp = NULL;

    tmp = calloc(1, sizeof(src_rcon_message_t));
    if (tmp == NULL) {
        return NULL;
    }

    tmp->body = calloc(1, sizeof(uint8_t));
    if (tmp->body == NULL) {
        free(tmp);
        return NULL;
    }

    tmp->type = serverdata_command;
    tmp->null = '\0';
    src_rcon_random_id(tmp);
    src_rcon_update_size(tmp);

    return tmp;
}

int32_t src_rcon_protocol(void)
{
    /* srcrcon is TCP
     */
    return SOCK_STREAM;
}

static void src_rcon_update_size(src_rcon_message_t *m)
{
    return_if_true(m == NULL,);

    m->size = sizeof(m->id);
    m->size += sizeof(m->type);
    m->size += strlen((char const *)m->body) + 1;
    m->size += sizeof(m->null);
}

static void src_rcon_random_id(src_rcon_message_t *m)
{
#ifdef HAVE_ARC4RANDOM_UNIFORM
    m->id = (int32_t)arc4random_uniform(INT32_MAX-1);
#else
    m->id = rand() % (INT32_MAX - 1);
#endif
}

static int src_rcon_body(src_rcon_message_t *m, char const *body)
{
    free(m->body);
    m->body = NULL;

    m->body = (uint8_t*)strdup(body);
    if (m->body == NULL) {
        return -1;
    }

    return 0;
}

src_rcon_message_t *src_rcon_command(char const *cmd)
{
    src_rcon_message_t *msg = NULL;

    msg = src_rcon_new();
    if (msg == NULL) {
        return NULL;
    }

    msg->type = serverdata_command;
    if (src_rcon_body(msg, cmd)) {
        src_rcon_free(msg);
        return NULL;
    }

    src_rcon_update_size(msg);

    return msg;
}

src_rcon_message_t *src_rcon_end_marker(src_rcon_message_t const *cmd)
{
    src_rcon_message_t *msg = NULL;

    msg = src_rcon_new();
    if (msg == NULL) {
        return NULL;
    }

    msg->type = serverdata_value;
    msg->id = cmd->id;

    src_rcon_update_size(msg);

    return msg;
}

rcon_error_t
src_rcon_command_wait(src_rcon_message_t const *cmd,
                      src_rcon_message_t ***replies,
                      size_t *off, void const *buf,
                      size_t size)
{
    src_rcon_message_t **p = NULL, **it = NULL;
    int ret = 0;
    size_t count = 0;
    size_t o = 0;
    int found = 0;

    ret = src_rcon_deserialize(&p, &o, &count, buf, size);
    if (ret) {
        return ret;
    }

    for (it = p; *it != NULL; it++) {
        if ((*it)->id == cmd->id && strlen((char const *)(*it)->body) == 0) {
            found = 1;
            break;
        }
    }

    if (!found) {
        src_rcon_freev(p);
        return rcon_error_moredata;
    }

    *off = o;
    *replies = p;

    return rcon_error_success;
}

src_rcon_message_t *src_rcon_auth(char const *password)
{
    src_rcon_message_t *msg = NULL;

    msg = src_rcon_new();
    if (msg == NULL) {
        return NULL;
    }

    msg->type = serverdata_auth;
    if (src_rcon_body(msg, password)) {
        src_rcon_free(msg);
        return NULL;
    }

    src_rcon_update_size(msg);

    return msg;
}

rcon_error_t
src_rcon_auth_wait(src_rcon_message_t const *auth, size_t *o,
                   void const *buf, size_t sz)
{
    src_rcon_message_t **p = NULL;
    size_t off = 0, count = 2;
    int ret = 0;

    ret = src_rcon_deserialize(&p, &off, &count, buf, sz);
    if (ret) {
        return ret;
    }

    if (count < 2) {
        src_rcon_freev(p);
        return rcon_error_moredata;
    }

    if (p[0]->type != serverdata_value &&
        p[1]->id != auth->id) {
        src_rcon_freev(p);
        return rcon_error_protocolerror;
    }

    if (p[1]->type != serverdata_auth_response) {
        src_rcon_freev(p);
        return rcon_error_protocolerror;
    }

    *o = off;

    if (p[1]->id != auth->id) {
        src_rcon_freev(p);
        return rcon_error_authinvalid;
    }

    src_rcon_freev(p);

    return rcon_error_success;
}

rcon_error_t
src_rcon_serialize(src_rcon_message_t const *m, uint8_t **buf, size_t *sz)
{
    uint8_t *tmp = NULL;
    size_t size = 0;
    FILE *str = NULL;

    return_if_true(m == NULL, -1);
    return_if_true(buf == NULL, -1);
    return_if_true(sz == NULL, -1);

    str = open_memstream((char**)&tmp, &size);
    if (str == NULL) {
        return rcon_error_memory;
    }

    fwrite(&m->size, 1, sizeof(m->size), str);
    fwrite(&m->id, 1, sizeof(m->id), str);
    fwrite(&m->type, 1, sizeof(m->id), str);
    if (m->body != NULL) {
        fwrite(m->body, 1, strlen((char const *)m->body), str);
    }
    fwrite(&m->null, 1, sizeof(m->null), str);
    fwrite(&m->null, 1, sizeof(m->null), str);

    if (m->type == serverdata_command) {
        /* Also serialize a marker
         */
        src_rcon_message_t *mk = src_rcon_end_marker(m);
        uint8_t *bufmk = NULL;
        size_t szmk = 0;

        if (mk == NULL) {
            fclose(str);
            free(tmp);
            return rcon_error_memory;
        }

        if (src_rcon_serialize(mk, &bufmk, &szmk) != rcon_error_success) {
            fclose(str);
            free(tmp);
            return rcon_error_unspecified;
        }

        fwrite(bufmk, 1, szmk, str);
        free(bufmk);
    }

    fclose(str);

    *buf = tmp;
    *sz = size;

    return rcon_error_success;
}

char const *src_rcon_get_body(src_rcon_message_t const *msg)
{
    return (char const *)msg->body;
}

rcon_error_t
src_rcon_deserialize(src_rcon_message_t ***msg, size_t *off,
                     size_t *cnt, void const *buf, size_t sz)
{
    uint32_t count = 1;
    FILE *str = NULL;
    src_rcon_message_t **res = NULL;

    return_if_true(msg == NULL, -1);
    return_if_true(off == NULL, -1);
    return_if_true(buf == NULL, -1);
    return_if_true(sz == 0, -1);

    str = fmemopen((char*)buf, sz, "r");
    if (str == NULL) {
        return rcon_error_memory;
    }

    do {
        src_rcon_message_t *m = NULL;
        src_rcon_message_t **tmp = NULL;
        size_t bufsize = 0;

        if (cnt && *cnt > 0) {
            if (count-1 > *cnt) {
                break;
            }
        }

        m = src_rcon_new();

        if (fread(&m->size, 1, sizeof(m->size), str) < sizeof(m->size)) {
            src_rcon_free(m);
            break;
        }

        if (fread(&m->id, 1, sizeof(m->id), str) < sizeof(m->id)) {
            src_rcon_free(m);
            break;
        }

        if (fread(&m->type, 1, sizeof(m->type), str) < sizeof(m->type)) {
            src_rcon_free(m);
            break;
        }

        bufsize = m->size - sizeof(m->id) - sizeof(m->type) - sizeof(m->null);
        free(m->body);
        m->body = calloc(1, bufsize+1);
        if (m->body == NULL) {
            src_rcon_free(m);
            return rcon_error_memory;
        }

        if (fread(m->body, 1, bufsize, str) < bufsize) {
            src_rcon_free(m);
            break;
        }

        if (fread(&m->null, 1, sizeof(m->null), str) < sizeof(m->null)) {
            src_rcon_free(m);
            break;
        }

        ++count;

        tmp = realloc(res, count * sizeof(src_rcon_message_t*));
        if (tmp == NULL) {
            src_rcon_freev(res);
            return rcon_error_memory;
        }
        res = tmp;

        tmp[count-2] = m;
        tmp[count-1] = NULL;
    } while(true);

    *off = ftell(str);
    fclose(str);

    if (res != NULL) {
        *msg = res;
        if (cnt) {
            *cnt = (count-1);
        }
        return rcon_error_success;
    }

    return rcon_error_moredata;
}
