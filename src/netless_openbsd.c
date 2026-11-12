#include <errno.h>
#include <stdio.h>
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
    /* OpenBSD removed the tmppath promise; tmpfile users need ordinary path promises. */
    const char *promises = "stdio rpath wpath cpath dpath proc exec prot_exec";
    int i = 1;
    if (i < argc && strcmp(argv[i], "--help") == 0) {
        puts("Usage: netless -- COMMAND [ARG...]\nRun COMMAND with OpenBSD pledge promises excluding inet, dns, and unix.");
        return 0;
    }
    if (i >= argc || strcmp(argv[i], "--") != 0 || i + 1 >= argc) {
        fprintf(stderr, "Usage: netless -- COMMAND [ARG...]\n");
        return 2;
    }
    if (refuse_socket_stdio() != 0) return 125;
    closefrom(3);
    /* Set both sets: children and exec'd descendants keep the same restrictions. */
    if (pledge(promises, promises) != 0) {
        perror("netless: pledge");
        return 125;
    }
    execvp(argv[i + 1], &argv[i + 1]);
    perror("netless: exec");
    return errno == ENOENT ? 127 : 126;
}
