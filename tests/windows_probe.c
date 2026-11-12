#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static int check_blocked(const char *name, int family, int type, int protocol,
                         const struct sockaddr *address, int address_len,
                         int operation) {
    SOCKET s = socket(family, type, protocol);
    if (s == INVALID_SOCKET) return 0;
    int result;
    if (operation == 0) result = bind(s, address, address_len);
    else if (operation == 1) result = connect(s, address, address_len);
    else {
        const char payload[] = "netless";
        result = sendto(s, payload, sizeof(payload), 0, address, address_len);
    }
    int blocked = result == SOCKET_ERROR;
    if (!blocked) fprintf(stderr, "FAIL: %s was allowed (WSA error %d)\n", name, WSAGetLastError());
    closesocket(s);
    return blocked;
}

static int probe(void) {
    int failures = 0;
    struct sockaddr_in loopback4 = {0};
    loopback4.sin_family = AF_INET;
    loopback4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct sockaddr_in remote4 = {0};
    remote4.sin_family = AF_INET;
    remote4.sin_port = htons(443);
    InetPtonA(AF_INET, "1.1.1.1", &remote4.sin_addr);
    struct sockaddr_in6 loopback6 = {0};
    loopback6.sin6_family = AF_INET6;
    loopback6.sin6_addr = in6addr_loopback;
    struct sockaddr_in6 remote6 = {0};
    remote6.sin6_family = AF_INET6;
    remote6.sin6_port = htons(443);
    InetPtonA(AF_INET6, "2606:4700:4700::1111", &remote6.sin6_addr);

    failures += !check_blocked("IPv4 loopback bind", AF_INET, SOCK_STREAM, IPPROTO_TCP,
                               (struct sockaddr *)&loopback4, sizeof(loopback4), 0);
    failures += !check_blocked("IPv4 outbound TCP connect", AF_INET, SOCK_STREAM, IPPROTO_TCP,
                               (struct sockaddr *)&remote4, sizeof(remote4), 1);
    failures += !check_blocked("IPv4 outbound UDP send", AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                               (struct sockaddr *)&remote4, sizeof(remote4), 2);
    failures += !check_blocked("IPv6 loopback bind", AF_INET6, SOCK_STREAM, IPPROTO_TCP,
                               (struct sockaddr *)&loopback6, sizeof(loopback6), 0);
    failures += !check_blocked("IPv6 outbound TCP connect", AF_INET6, SOCK_STREAM, IPPROTO_TCP,
                               (struct sockaddr *)&remote6, sizeof(remote6), 1);

    char unique_host[96];
    (void)snprintf(unique_host, sizeof(unique_host), "netless-%lu-%lu.example.com",
                   (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_UNSPEC;
    int dns = getaddrinfo(unique_host, "443", &hints, &result);
    if (dns == 0) {
        fprintf(stderr, "FAIL: DNS lookup for unique external name succeeded\n");
        failures++;
        freeaddrinfo(result);
    }

    SOCKET raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw != INVALID_SOCKET) {
        fprintf(stderr, "FAIL: raw IPv4 socket creation was allowed\n");
        failures++;
        closesocket(raw);
    }
    return failures;
}

int wmain(int argc, wchar_t **argv) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 10;
    int failed = probe();
    if (argc == 1 && failed == 0) {
        wchar_t self[MAX_PATH];
        if (!GetModuleFileNameW(NULL, self, MAX_PATH)) {
            fprintf(stderr, "FAIL: cannot resolve probe path\n");
            failed++;
        } else {
            wchar_t command[MAX_PATH + 16];
            (void)swprintf_s(command, MAX_PATH + 16, L"\"%ls\" --child", self);
            STARTUPINFOW startup = {0};
            startup.cb = sizeof(startup);
            PROCESS_INFORMATION child = {0};
            if (!CreateProcessW(self, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &child)) {
                fprintf(stderr, "FAIL: cannot start descendant probe (error %lu)\n",
                        (unsigned long)GetLastError());
                failed++;
            } else {
                WaitForSingleObject(child.hProcess, INFINITE);
                DWORD code = 1;
                (void)GetExitCodeProcess(child.hProcess, &code);
                CloseHandle(child.hThread);
                CloseHandle(child.hProcess);
                if (code != 0) failed++;
            }
        }
    } else if (argc > 1 && wcscmp(argv[1], L"--child") == 0 && failed != 0) {
        fprintf(stderr, "FAIL: descendant network probe failed\n");
    }
    WSACleanup();
    return failed == 0 ? 0 : 1;
}
