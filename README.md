# netless

Run a Unix-like command with kernel-enforced denial of network access. Network access is denied by default; this program has no option to turn it back on.

```sh
make
./build/netless -- curl https://example.com
```

The command still runs. `curl` will fail when it tries to create a socket. Ordinary file, process, and terminal operations remain available.

On Linux, additional syscalls from the built-in table can be denied by name:

```sh
./build/netless --deny-syscall ptrace --deny-syscall mount -- COMMAND ARGUMENTS
```

The launcher needs the platform's native compiler and kernel sandbox support. Build with `make`; install with `sudo make install` (default `/usr/local/bin`).

## Platform support

| Platform | Enforcement | Architectures | Status |
|---|---|---|---|
| Linux | seccomp-BPF; blocks socket and `io_uring` syscalls | x86-64, AArch64 | Implemented; local AArch64 tests pass, CI builds both |
| macOS | Seatbelt sandbox profile `(deny network*)`; inherited by child processes | Intel x86-64, Apple Silicon arm64 | Native adapter; CI and release builds run on native macOS runners |
| OpenBSD | `pledge` without `inet`, `dns`, or `unix`; same promises applied to exec descendants | Native OpenBSD architectures | Adapter source included; needs native OpenBSD CI validation before binary release |
| FreeBSD | — | — | Not supported yet: Capsicum capability mode alone does not deny creation of new network sockets |
| Solaris / illumos, NetBSD, other Unix | — | — | Not supported yet; no verified kernel enforcement adapter |
| Windows | — | — | Separate implementation required; out of scope for this release |

“Unix-like” is not one portable security API. This project only claims support for adapters that use an OS-enforced policy inherited by descendants. Unsupported systems fail at build selection instead of falling back to a weak wrapper.

## What it enforces

- Linux installs a seccomp-BPF filter before `exec`. The filter returns `EPERM` for socket creation and use syscalls, covering IPv4, IPv6, raw, packet, Unix-domain, and other socket families alike.
- Denies `io_uring` setup, entry, and registration, so it cannot be used to submit socket operations through the asynchronous interface.
- Denies `pidfd_getfd` and `ptrace`; closes inherited file descriptors above stderr; refuses to start if stdin, stdout, or stderr is a socket.
- Sets `no_new_privs` before installing the filter. If setting the flag or installing the filter fails, the target command is never executed.
- Linux filters are inherited by forked/cloned children and survive exec, as enforced by the kernel. OpenBSD applies pledge exec promises to descendants. macOS Seatbelt restrictions are inherited by child processes.

This restricts network access for the launched process tree under each supported OS policy. It does not sandbox filesystem access, resource use, or interaction with a separate privileged broker/service that independently performs network operations on request. Keep untrusted workloads away from cooperating host services and do not treat this as a full container or VM boundary.

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
- [OpenBSD pledge(2)](https://man.openbsd.org/pledge)
- [Apple App Sandbox inheritance](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [FreeBSD Capsicum](https://man.freebsd.org/cgi/man.cgi?query=capsicum&sektion=4)

## License

MIT. See [LICENSE](LICENSE).
