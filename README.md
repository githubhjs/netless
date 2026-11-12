# netless

Run a Linux command with kernel-enforced denial of socket and asynchronous-I/O networking syscalls. Network access is denied by default; this program has no option to turn it back on.

```sh
make
./build/netless -- curl https://example.com
```

The command still runs. `curl` will fail when it tries to create a socket. Ordinary file, process, and terminal operations remain available.

Additional syscalls can be denied by name:

```sh
./build/netless --deny-syscall ptrace --deny-syscall mount -- COMMAND ARGUMENTS
```

The extra-denial names are the syscall names in the built-in table (`--help` lists usage; unsupported names fail closed). The launcher needs a Linux kernel with seccomp filter support and a C compiler to build. It supports native x86-64 and AArch64 binaries. Other syscall ABIs are killed by the architecture check. Build with `make`; install with `sudo make install` (default `/usr/local/bin`).

## What it enforces

- Installs a Linux seccomp-BPF filter before `exec`. The filter returns `EPERM` for socket creation and use syscalls, covering IPv4, IPv6, raw, packet, Unix-domain, and other socket families alike.
- Denies `io_uring` setup, entry, and registration, so it cannot be used to submit socket operations through the asynchronous interface.
- Denies `pidfd_getfd` and `ptrace`; closes inherited file descriptors above stderr; refuses to start if stdin, stdout, or stderr is a socket.
- Sets `no_new_privs` before installing the filter. If setting the flag or installing the filter fails, the target command is never executed.
- The filter is inherited by forked/cloned children and survives exec, as enforced by the Linux kernel.

This provides a syscall-level guarantee for the launched process tree under the supported Linux syscall ABI. It does not sandbox filesystem access, resource use, or interaction with a separate privileged broker/service that independently performs network operations on request. Keep untrusted workloads away from cooperating host services and do not treat this as a full container or VM boundary. Network syscalls are denied; the whole syscall interface remains enabled apart from the listed calls and any extra denials. Linux documentation notes that seccomp is a filter mechanism, not a general-purpose sandbox.

The program does not modify firewall rules, routes, DNS configuration, network namespaces, or host networking. No root privilege is required to run it when the kernel permits an unprivileged process to set `no_new_privs` and seccomp filters.

## Verification

```sh
make test
```

Tests exercise DNS/socket denial, IPv4/IPv6/raw socket creation, inherited descriptor closure, and filter inheritance across fork and exec. A passing local test is evidence for that kernel/build; review the code and kernel configuration before relying on it in a high-assurance deployment.

## References

- [Linux kernel seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [PR_SET_NO_NEW_PRIVS(2)](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)

## License

MIT. See [LICENSE](LICENSE).
