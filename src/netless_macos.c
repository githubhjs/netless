#define _DARWIN_C_SOURCE
#include <errno.h>
#include <sandbox.h>
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
    int i = 1;
    if (i < argc && strcmp(argv[i], "--help") == 0) {
        puts("Usage: netless -- COMMAND [ARG...]\nRun COMMAND under macOS Seatbelt with all network operations denied.");
        return 0;
    }
    if (i >= argc || strcmp(argv[i], "--") != 0 || i + 1 >= argc) {
        fprintf(stderr, "Usage: netless -- COMMAND [ARG...]\n");
        return 2;
    }
    if (refuse_socket_stdio() != 0) return 125;
    closefrom(3);
    char *error = NULL;
    if (sandbox_init("(version 1) (deny network*)", 0, &error) != 0) {
        fprintf(stderr, "netless: sandbox_init failed: %s\n", error ? error : "unknown error");
        if (error) sandbox_free_error(error);
        return 125;
    }
    execvp(argv[i + 1], &argv[i + 1]);
    perror("netless: exec");
    return errno == ENOENT ? 127 : 126;
}
