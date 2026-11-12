#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>

static int refuse_socket_stdio(void) {
    for (int fd = 0; fd < 3; ++fd) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode)) {
            fprintf(stderr, "netless: refusing inherited socket on fd %d\n", fd);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--help") == 0) {
        puts("Usage: netless -- COMMAND [ARG...]\n"
             "Run COMMAND in a FreeBSD jail with IPv4 and IPv6 disabled.\n"
             "Requires root or equivalent jail-management privilege.");
        return 0;
    }
    if (argc < 3 || strcmp(argv[1], "--") != 0) {
        fprintf(stderr, "Usage: netless -- COMMAND [ARG...]\n");
        return 2;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "netless: FreeBSD jail backend requires root (or jail privilege)\n");
        return 125;
    }
    if (refuse_socket_stdio() != 0) return 125;
    closefrom(3);

    /*
     * A jail without IP addresses has no IPv4/IPv6 networking. Also deny
     * raw sockets and nonstandard address families explicitly. AF_LOCAL
     * remains available, so this is best-effort rather than a syscall-wide
     * denial of socket creation.
     */
    size_t n = (size_t)argc + 10;
    char **jail_argv = calloc(n, sizeof(*jail_argv));
    if (!jail_argv) { perror("netless: calloc"); return 125; }
    int k = 0;
    jail_argv[k++] = (char *)"/usr/sbin/jail";
    jail_argv[k++] = (char *)"-c";
    char jail_name[64];
    (void)snprintf(jail_name, sizeof(jail_name), "name=netless-%ld", (long)getpid());
    jail_argv[k++] = jail_name;
    jail_argv[k++] = (char *)"path=/";
    jail_argv[k++] = (char *)"host.hostname=netless";
    jail_argv[k++] = (char *)"ip4=disable";
    jail_argv[k++] = (char *)"ip6=disable";
    jail_argv[k++] = (char *)"allow.raw_sockets=0";
    jail_argv[k++] = (char *)"allow.socket_af=0";
    size_t command_len = strlen(argv[2]) + sizeof("command=");
    char *command = malloc(command_len);
    if (!command) { perror("netless: malloc"); free(jail_argv); return 125; }
    (void)snprintf(command, command_len, "command=%s", argv[2]);
    jail_argv[k++] = command;
    for (int i = 3; i < argc; ++i) jail_argv[k++] = argv[i];
    jail_argv[k] = NULL;
    execv(jail_argv[0], jail_argv);
    perror("netless: exec jail");
    return errno == ENOENT ? 127 : 126;
}
