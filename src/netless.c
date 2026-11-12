#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NETLESS_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NETLESS_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "netless supports only x86_64 and aarch64 Linux"
#endif

#define MAX_EXTRA 32
#define MAX_FILTER 128
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

struct blocked_call { const char *name; int number; };

#define CALL(n) { #n, SYS_##n }
static const struct blocked_call network_calls[] = {
    CALL(socket), CALL(socketpair), CALL(connect), CALL(bind), CALL(listen),
    CALL(accept), CALL(accept4), CALL(sendto), CALL(recvfrom), CALL(sendmsg),
    CALL(recvmsg), CALL(shutdown), CALL(getsockname), CALL(getpeername),
    CALL(setsockopt), CALL(getsockopt),
#ifdef SYS_io_uring_setup
    CALL(io_uring_setup), CALL(io_uring_register), CALL(io_uring_enter),
#endif
#ifdef SYS_pidfd_getfd
    CALL(pidfd_getfd),
#endif
#ifdef SYS_ptrace
    CALL(ptrace),
#endif
};
#undef CALL

static void usage(FILE *out) {
    fprintf(out,
        "Usage: netless [--deny-syscall NAME]... -- COMMAND [ARG...]\n"
        "Run COMMAND with kernel-enforced socket and io_uring denial.\n"
        "Additional syscall denials may be added by name. Network access\n"
        "cannot be enabled by this launcher.\n");
}

static int lookup_syscall(const char *name) {
    for (size_t i = 0; i < ARRAY_LEN(network_calls); ++i)
        if (strcmp(name, network_calls[i].name) == 0)
            return network_calls[i].number;
    return -1;
}

static int is_socket_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return 0;
    return S_ISSOCK(st.st_mode);
}

static int close_inherited_fds(void) {
    for (int fd = 0; fd <= 2; ++fd) {
        if (is_socket_fd(fd)) {
            fprintf(stderr, "netless: refusing inherited socket on fd %d\n", fd);
            return -1;
        }
    }
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) return 0;
    if (errno != ENOSYS && errno != EINVAL) {
        perror("netless: close_range");
        return -1;
    }
#endif
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        perror("netless: getrlimit");
        return -1;
    }
    rlim_t end = limit.rlim_cur == RLIM_INFINITY ? 1048576 : limit.rlim_cur;
    for (rlim_t fd = 3; fd < end; ++fd)
        if (close((int)fd) != 0 && errno != EBADF) {
            perror("netless: close inherited fd");
            return -1;
        }
    return 0;
}

static int install_filter(const int *extra, size_t extra_count) {
    struct sock_filter code[MAX_FILTER];
    size_t n = 0;
    code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                            offsetof(struct seccomp_data, arch));
    code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                            NETLESS_AUDIT_ARCH, 1, 0);
    /* KILL_THREAD is supported by older seccomp-filter kernels than KILL_PROCESS. */
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD);
    code[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                                            offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                                            __X32_SYSCALL_BIT, 0, 1);
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_THREAD);
#endif
    for (size_t i = 0; i < ARRAY_LEN(network_calls); ++i) {
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                (uint32_t)network_calls[i].number, 0, 1);
        code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                                SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }
    for (size_t i = 0; i < extra_count; ++i) {
        code[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                                (uint32_t)extra[i], 0, 1);
        code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K,
                                                SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }
    code[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    if (n > MAX_FILTER) {
        fprintf(stderr, "netless: filter too large\n");
        return -1;
    }
    struct sock_fprog program = { .len = (unsigned short)n, .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("netless: PR_SET_NO_NEW_PRIVS");
        return -1;
    }
    /* PR_SET_SECCOMP predates the seccomp(2) syscall (Linux 3.17). */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
        perror("netless: installing seccomp filter (kernel needs CONFIG_SECCOMP_FILTER)");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    int extra[MAX_EXTRA];
    size_t extra_count = 0;
    int i = 1;
    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (strcmp(argv[i], "--help") == 0) { usage(stdout); return 0; }
        if (strcmp(argv[i], "--deny-syscall") != 0 || i + 1 >= argc) {
            usage(stderr); return 2;
        }
        int number = lookup_syscall(argv[i + 1]);
        if (number < 0) {
            fprintf(stderr, "netless: unsupported syscall name: %s\n", argv[i + 1]);
            return 2;
        }
        if (extra_count == MAX_EXTRA) {
            fprintf(stderr, "netless: too many additional syscall denials\n");
            return 2;
        }
        extra[extra_count++] = number;
        i += 2;
    }
    if (i >= argc || i + 1 >= argc) { usage(stderr); return 2; }
    if (close_inherited_fds() != 0 || install_filter(extra, extra_count) != 0) return 125;
    execvp(argv[i + 1], &argv[i + 1]);
    perror("netless: exec");
    return errno == ENOENT ? 127 : 126;
}
