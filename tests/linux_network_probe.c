#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int expect_seccomp_denial(const char *name, int domain, int type, int protocol) {
    int fd = socket(domain, type, protocol);
    if (fd >= 0) {
        fprintf(stderr, "FAIL: %s socket was created\n", name);
        close(fd);
        return 1;
    }
    if (errno != EPERM) {
        fprintf(stderr, "FAIL: %s socket failed with errno %d, expected EPERM\n", name, errno);
        return 1;
    }
    return 0;
}

static int probe(void) {
    int failures = 0;
    failures += expect_seccomp_denial("IPv4 stream", AF_INET, SOCK_STREAM, 0);
    failures += expect_seccomp_denial("IPv6 datagram", AF_INET6, SOCK_DGRAM, 0);
    failures += expect_seccomp_denial("raw packet", AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0) {
        fprintf(stderr, "FAIL: Unix socketpair was created\n");
        close(pair[0]);
        close(pair[1]);
        failures++;
    } else if (errno != EPERM) {
        fprintf(stderr, "FAIL: Unix socketpair failed with errno %d, expected EPERM\n", errno);
        failures++;
    }
    return failures;
}

int main(int argc, char **argv) {
    int failures = probe();
    if (failures != 0 || (argc > 1 && strcmp(argv[1], "--child") == 0))
        return failures ? 1 : 0;

    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (child == 0) {
        execl(argv[0], argv[0], "--child", (char *)NULL);
        perror("exec child probe");
        _exit(127);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) { perror("waitpid"); return 1; }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: child process escaped or failed network probe\n");
        return 1;
    }
    return 0;
}
