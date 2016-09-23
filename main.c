#include "rcon.h"
#include "config.h"
#include "srcrcon.h"

#include <glib.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

static char *host = NULL;
static char *password = NULL;
static char *port = NULL;
static char *config = NULL;
static char *server = NULL;

static uint32_t socktype = 0;
static struct addrinfo *sinfo = NULL;

static rcon_proto_t *proto = NULL;

static GByteArray *response = NULL;

static void cleanup(void)
{
    config_free();

    free(host);
    free(password);
    free(port);
    free(config);
    free(server);

    if (response) {
        g_byte_array_free(response, TRUE);
    }
}

static void usage(void)
{
    puts("");
    puts("Usage:");
    puts(" rcon [options] command");
    puts("");
    puts("Options:");
    puts(" -c, --config     Alternate configuration file");
    puts(" -h, --help       This bogus");
    puts(" -H, --host       Host name or IP");
    puts(" -P, --password   RCON Password");
    puts(" -p, --port       Port or service");
    puts(" -s, --server     Use this server from config file");
    puts(" -t, --type       Type of the server: source, battleye");
}

static int parse_args(int ac, char **av)
{
    static struct option opts[] = {
        { "config", required_argument, 0, 'c' },
        { "help", no_argument, 0, 'h' },
        { "host", required_argument, 0, 'H' },
        { "password", required_argument, 0, 'P' },
        { "port", required_argument, 0, 'p' },
        { "server", required_argument, 0, 's' },
        { "type", required_argument, 0, 't' },
        { NULL, 0, 0, 0 }
    };

    static char const *optstr = "c:Hh:P:p:s:";

    int c = 0;

    while ((c = getopt_long(ac, av, optstr, opts, NULL)) != -1) {
        switch (c)
        {
        case 'c': free(config); config = strdup(optarg); break;
        case 'H': free(host); host = strdup(optarg); break;
        case 'p': free(port); port = strdup(optarg); break;
        case 'P': free(password); password = strdup(optarg); break;
        case 's': free(server); server = strdup(optarg); break;
        case 'h': usage(); exit(0); break;
        case 't':
        {
            proto = rcon_proto_by_name(optarg);
            if (proto == NULL) {
                fprintf(stderr, "Invalid protocol: %s\n", optarg);
                exit(1);
            }
        } break;
        default: /* intentional */
        case '?': usage(); exit(1); break;
        }
    }

    return 0;
}

static int send_message(int sock, void *msg)
{
    uint8_t *data = NULL;
    uint8_t *p = NULL;
    size_t size = 0;
    int ret = 0;

    if (proto->serialize(msg, &data, &size)) {
        return -1;
    }

    p = data;
    do {
        if (socktype == SOCK_STREAM) {
            ret = write(sock, p, size);
        } else if (socktype == SOCK_DGRAM) {
            ret = sendto(sock, p, size, 0, sinfo->ai_addr, sinfo->ai_addrlen);
        }
        if (ret == 0 || ret < 0) {
            free(data);
            fprintf(stderr, "Failed to communicate: %s\n", strerror(errno));
            return -2;
        }

        p += ret;
        size -= ret;
    } while (size > 0);

    free(data);

    return 0;
}

static int wait_auth(int sock, void *auth)
{
    uint8_t tmp[512];
    int ret = 0;
    rcon_error_t status;
    size_t off = 0;

    do {
        ret = read(sock, tmp, sizeof(tmp));
        if (ret < 0) {
            fprintf(stderr, "Failed to receive data: %s\n", strerror(errno));
            return -1;
        }

        g_byte_array_append(response, tmp, ret);

        status = proto->auth_wait(auth, &off, response->data, response->len);
        if (status != rcon_error_moredata) {
            g_byte_array_remove_range(response, 0, off);
            return (int)status;
        }
    } while (true);

    return 1;
}

static int send_command(int sock, char const *cmd)
{
    void *command = NULL;
    void **commandanswers = NULL;
    void **p = NULL;
    uint8_t tmp[512];
    int ret = 0;
    rcon_error_t status;
    size_t off = 0;
    int ec = -1;

    /* Send command
     */
    command = src_rcon_command(cmd);
    if (command == NULL) {
        goto cleanup;
    }

    if (send_message(sock, command)) {
        goto cleanup;
    }

    do {
        ret = read(sock, tmp, sizeof(tmp));
        if (ret < 0) {
            fprintf(stderr, "Failed to receive data: %s\n", strerror(errno));
            return -1;
        }

        g_byte_array_append(response, tmp, ret);
        status = proto->command_wait(command, &commandanswers, &off,
                                     response->data, response->len);
        if (status != rcon_error_moredata) {
            g_byte_array_remove_range(response, 0, off);
            break;
        }
    } while (true);

    for (p = commandanswers; *p != NULL; p++) {
        fprintf(stdout, "%s", proto->get_body(*p));
        fflush(stdout);
    }

    ec = 0;

cleanup:

    proto->free(command);
    proto->freev(commandanswers);

    return ec;
}

static int handle_arguments(int sock, int ac, char **av)
{
    char *c = NULL;
    size_t size = 0;
    FILE *cmd = NULL;
    int i = 0;

    cmd = open_memstream(&c, &size);
    if (cmd == NULL) {
        return -1;
    }

    for (i = 0; i < ac; i++) {
        if (i > 0) {
            fputc(' ', cmd);
        }
        fprintf(cmd, "%s", av[i]);
    }
    fclose(cmd);

    if (send_command(sock, c)) {
        free(c);
        return -1;
    }

    free(c);

    return 0;
}

static int handle_stdin(int sock)
{
    char *line = NULL;
    size_t sz = 0;
    int read = 0;
    int ec = 0;

    while ((read = getline(&line, &sz, stdin)) != -1) {
        char *cmd = line;

        /* Strip away \n
         */
        line[read-1] = '\0';

        while (*cmd != '\0' && isspace(*cmd)) {
            ++cmd;
        }

        /* Comment or empty line
         */
        if (cmd[0] == '\0' || cmd[0] == '#') {
            continue;
        }

        if (send_command(sock, cmd)) {
            ec = -1;
            break;
        }
    }

    free(line);

    return ec;
}

int do_config(void)
{
    if (server == NULL) {
        return 0;
    }

    if (config == NULL) {
        char const *home = getenv("HOME");
        size_t sz = 0;

        if (home == NULL) {
            fprintf(stderr, "Neither config file nor $HOME is set\n");
            return 4;
        }

        sz = strlen(home) + 10;
        config = calloc(1, sz);
        if (config == NULL) {
            return 4;
        }

        g_strlcpy(config, getenv("HOME"), sz);
        g_strlcat(config, "/.rconrc", sz);
    }

    if (config_load(config)) {
        return 2;
    }

    free(host);
    free(port);
    free(password);

    if (config_host_data(server, &host, &port, &password, &proto)) {
        fprintf(stderr, "Server %s not found in configuration\n", server);
        return 2;
    }

    return 0;
}

int main(int ac, char **av)
{
    struct addrinfo *info = NULL, *ai = NULL, hint = {0};
    void *auth = NULL;
    int sock = 0;
    int ret = 0;
    int ec = 3;

    atexit(cleanup);

    parse_args(ac, av);
    if (do_config()) {
        return 2;
    }
    /* Now parse arguments *again*. This allows for overrides on the command
     * line.
     */
    optind = 1;
    parse_args(ac, av);


    ac -= optind;
    av += optind;

    if (host == NULL || port == NULL) {
        fprintf(stderr, "No host and/or port specified\n");
        return 1;
    }

    if (proto == NULL) {
        proto = rcon_proto_default();
    }

    socktype = proto->protocol();

    memset(&hint, 0, sizeof(hint));
    hint.ai_socktype = socktype;
    hint.ai_family = AF_UNSPEC;
    hint.ai_flags = AI_PASSIVE;

    if ((ret = getaddrinfo(host, port, &hint, &info))) {
        fprintf(stderr, "Failed to resolve host: %s: %s\n",
                host, gai_strerror(ret)
            );
        goto cleanup;
    }

    for (ai = info; ai != NULL; ai = ai->ai_next ) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            continue;
        }

        if (socktype == SOCK_STREAM) {
            if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
                break;
            }
        } else if (socktype == SOCK_DGRAM) {
            sinfo = ai;
            break;
        }

        close(sock);
        sock = -1;
    }

    if (sock < 0) {
        fprintf(stderr, "Failed to connect to the given host/service\n");
        goto cleanup;
    }

    response = g_byte_array_new();

    /* Do we have a password? And support for password auth?
     */
    if (password != NULL && strlen(password) > 0 && proto->auth != NULL) {
        /* Send auth request first
         */
        auth = proto->auth(password);

        if (send_message(sock, auth)) {
            goto cleanup;
        }

        if (wait_auth(sock, auth)) {
            fprintf(stderr, "Invalid auth reply, valid password?\n");
            goto cleanup;
        }
    }

    if (ac > 0) {
        if (handle_arguments(sock, ac, av)) {
            goto cleanup;
        }
    } else {
        if (handle_stdin(sock)) {
            goto cleanup;
        }
    }


    ec = 0;

cleanup:

    proto->free(auth);

    if (sock > -1) {
        close(sock);
    }

    if (info) {
        freeaddrinfo(info);
    }

    return ec;
}
