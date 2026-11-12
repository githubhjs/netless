# netless

Run a command with OS-enforced restrictions on network access. Network access is denied by default; this program has no option to turn it back on.

```sh
make
./build/netless -- curl https://example.com
```

The command still runs. `curl` will fail when it tries to create a socket. Ordinary file, process, and terminal operations remain available.

On Linux, additional syscalls from the built-in table can be denied by name:

```sh
./build/netless --deny-syscall ptrace --deny-syscall mount -- COMMAND ARGUMENTS
```

The launcher needs the platform's native compiler and sandbox support. On Linux and macOS build with `make`; install with `sudo make install` (default `/usr/local/bin`). On Windows, run `scripts/build-windows.ps1` from a Visual Studio Developer PowerShell.

## Platform support

| Platform | Enforcement | Architectures | Status |
|---|---|---|---|
| Linux | seccomp-BPF; blocks socket and `io_uring` syscalls | x86-64, AArch64 | Implemented and CI-tested |
| macOS | Seatbelt sandbox via `sandbox-exec`; denies `network*` and `system-socket`; descendants inherit policy | Intel x86-64, Apple Silicon arm64 | Implemented and CI-tested; binaries published in releases |
| OpenBSD | `pledge` without `inet`, `dns`, or `unix`; same promises applied to exec descendants | x86-64 release; other native architectures may build | Implemented and tested in an OpenBSD VM; release binary available |
| FreeBSD | Jail with IPv4/IPv6 disabled and raw sockets denied | x86-64 release | Best effort; requires root, leaves AF_LOCAL available, and uses the host filesystem as the jail root |
| Solaris / illumos, NetBSD, other Unix | — | — | Not supported yet; no verified kernel enforcement adapter |
| Windows 10/11 | AppContainer with no network capabilities; descendant processes inherit the container identity | x86-64 and ARM64 releases; tested on Windows Server 2022 x64 and Windows 11 ARM64 | Best effort; API baseline supports Windows 10/11, but Windows 10 is not yet a CI image; AppContainer also restricts filesystem, registry, and IPC access |

“Unix-like” is not one portable security API. Linux, macOS, and OpenBSD use inherited kernel policies to deny network operations. FreeBSD and Windows use platform sandboxes with additional limitations; see the table above. Unsupported systems fail at build selection instead of silently falling back to an unconfined launch.

## What it enforces

- Linux installs a seccomp-BPF filter before `exec`. The filter returns `EPERM` for socket creation and use syscalls, covering IPv4, IPv6, raw, packet, Unix-domain, and other socket families alike.
- Denies `io_uring` setup, entry, and registration, so it cannot be used to submit socket operations through the asynchronous interface.
- Denies `pidfd_getfd` and `ptrace`; closes inherited file descriptors above stderr; refuses to start if stdin, stdout, or stderr is a socket.
- Sets `no_new_privs` before installing the filter. If setting the flag or installing the filter fails, the target command is never executed.
- Linux filters are inherited by forked/cloned children and survive exec, as enforced by the kernel. OpenBSD applies pledge exec promises to descendants. macOS Seatbelt restrictions are inherited by child processes. Windows child processes inherit their AppContainer identity.
- FreeBSD jails have IPv4 and IPv6 disabled and raw sockets disabled. AF_LOCAL remains available, and the jail sees the host root filesystem, so local Unix-domain sockets can reach host services that may themselves provide network access. Treat this mode as best effort only, especially for untrusted commands.
- Windows uses a fresh AppContainer identity per launch and grants no network capabilities. The Windows kernel isolates the command and its descendants, but AppContainer also restricts filesystem, registry, and IPC access. The launcher passes only standard handles, refuses socket-backed standard handles, and does not grant loopback exemptions. Windows CI confirmed that AppContainer still allows socket creation, local binds, raw-socket creation, and UDP send calls; its tests separately probe whether TCP, DNS, UDP responses, and loopback traffic actually reach a peer. This backend therefore cannot promise syscall-level socket denial or zero packet egress. It does not install WFP filters or a custom kernel driver. Explicit per-AppContainer WFP filters would require elevated filter-management permission and are not installed by this project.

Linux, macOS, and OpenBSD deny network socket operations in the launched process tree under their OS-enforced policies. Windows AppContainer and FreeBSD jail provide best-effort isolation with the limitations described above. No backend blocks a separate privileged broker/service that independently performs network operations on request. Keep untrusted workloads away from cooperating host services and do not treat this as a full container or VM boundary.

The program does not modify firewall rules, routes, DNS configuration, network namespaces, or host networking. No root privilege is required to run it when the kernel permits an unprivileged process to set `no_new_privs` and seccomp filters.

## Verification

```sh
make test
```

Tests attempt DNS resolution, IPv4/IPv6 loopback binds, outbound TCP connections, UDP sends, raw socket creation, inherited descriptor closure, and descendant process network access. Windows uses a dedicated Winsock probe and tests child-process inheritance. BSD CI runs in native virtual machines; Linux/macOS and Windows CI run on their respective hosted runners. A passing test is evidence for that specific OS image and architecture; review the code and OS configuration before relying on it in a high-assurance deployment.

## Windows build and test

From a Visual Studio Developer PowerShell on Windows 10 or 11:

```powershell
./scripts/build-windows.ps1
./tests/test_windows.ps1
```

AppContainer requires no administrator rights for the network restriction itself. Programs that need to read or execute files outside locations already accessible to AppContainer identities may need explicit ACL changes; netless does not modify those ACLs automatically. Windows CI grants read/execute access only to its disposable test directory so it can run the adversarial probe.

## References

- [Linux kernel seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [PR_SET_NO_NEW_PRIVS(2)](https://man7.org/linux/man-pages/man2/PR_SET_NO_NEW_PRIVS.2const.html)
- [OpenBSD pledge(2)](https://man.openbsd.org/pledge)
- [Apple App Sandbox inheritance](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [FreeBSD Capsicum](https://man.freebsd.org/cgi/man.cgi?query=capsicum&sektion=4)
- [FreeBSD jail(8)](https://man.freebsd.org/cgi/man.cgi?query=jail&sektion=8)
- [Microsoft: Launch an AppContainer](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer)
- [Microsoft: SECURITY_CAPABILITIES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_capabilities)
- [Microsoft: AppContainer for legacy applications](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-for-legacy-applications-)

## License

MIT. See [LICENSE](LICENSE).
