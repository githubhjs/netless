#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static int check_blocked(const char *name, int family, int type, int protocol,
                         const struct sockaddr *address, int address_len,
                         int operation, int network_success_is_failure) {
    SOCKET s = socket(family, type, protocol);
    if (s == INVALID_SOCKET) return 0;
    int result;
    if (operation == 0) result = bind(s, address, address_len);
    else if (operation == 1) result = connect(s, address, address_len);
    else {
        const char payload[] = "netless";
        result = sendto(s, payload, sizeof(payload), 0, address, address_len);
    }
    int failed = 0;
    if (operation == 0 && result == 0)
        fprintf(stderr, "LIMITATION: %s succeeded; AppContainer permits local port binding\n", name);
    else if (operation == 2 && result == 0)
        fprintf(stderr, "INFO: %s API accepted a datagram; checking whether it reached a receiver\n", name);
    else if (operation == 1 && result == 0) {
        fprintf(stderr, "FAIL: %s connected successfully\n", name);
        failed = network_success_is_failure;
    }
    closesocket(s);
    return failed;
}

static int test_udp_dns_response(void) {
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return 0;
    DWORD timeout = 2000;
    (void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    const unsigned char query[] = {
        0x4e, 0x4c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e','x','a','m','p','l','e', 0x03, 'c','o','m', 0x00,
        0x00, 0x01, 0x00, 0x01
    };
    struct sockaddr_in dns = {0};
    dns.sin_family = AF_INET;
    dns.sin_port = htons(53);
    InetPtonA(AF_INET, "8.8.8.8", &dns.sin_addr);
    int sent = sendto(s, (const char *)query, sizeof(query), 0,
                      (struct sockaddr *)&dns, sizeof(dns));
    char response[512];
    int received = SOCKET_ERROR;
    if (sent != SOCKET_ERROR) {
        struct sockaddr_in from;
        int from_len = sizeof(from);
        received = recvfrom(s, response, sizeof(response), 0,
                            (struct sockaddr *)&from, &from_len);
    }
    if (received > 0) {
        fprintf(stderr, "FAIL: received a DNS response from 8.8.8.8\n");
        closesocket(s);
        return 1;
    }
    if (sent != SOCKET_ERROR)
        fprintf(stderr, "INFO: DNS send was accepted but no response reached the process\n");
    closesocket(s);
    return 0;
}

static int test_loopback_delivery(void) {
    int failures = 0;
    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server != INVALID_SOCKET) {
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(server, (struct sockaddr *)&local, sizeof(local)) == 0 && listen(server, 1) == 0) {
            int length = sizeof(local);
            if (getsockname(server, (struct sockaddr *)&local, &length) == 0) {
                SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (client != INVALID_SOCKET) {
                    if (connect(client, (struct sockaddr *)&local, sizeof(local)) == 0) {
                        fprintf(stderr, "FAIL: AppContainer TCP loopback reached its listener\n");
                        failures++;
                    }
                    closesocket(client);
                }
            }
        }
        closesocket(server);
    }

    SOCKET receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (receiver != INVALID_SOCKET) {
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(receiver, (struct sockaddr *)&local, sizeof(local)) == 0) {
            int length = sizeof(local);
            if (getsockname(receiver, (struct sockaddr *)&local, &length) == 0) {
                DWORD timeout = 500;
                (void)setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
                SOCKET sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (sender != INVALID_SOCKET) {
                    const char payload[] = "netless-local-probe";
                    (void)sendto(sender, payload, sizeof(payload), 0,
                                 (struct sockaddr *)&local, sizeof(local));
                    char received[64];
                    if (recv(receiver, received, sizeof(received), 0) > 0) {
                        fprintf(stderr, "FAIL: AppContainer UDP loopback reached its listener\n");
                        failures++;
                    }
                    closesocket(sender);
                }
            }
        }
        closesocket(receiver);
    }
    return failures;
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

    failures += check_blocked("IPv4 loopback bind", AF_INET, SOCK_STREAM, IPPROTO_TCP,
                              (struct sockaddr *)&loopback4, sizeof(loopback4), 0, 0);
    failures += check_blocked("IPv4 outbound TCP connect", AF_INET, SOCK_STREAM, IPPROTO_TCP,
                              (struct sockaddr *)&remote4, sizeof(remote4), 1, 1);
    failures += check_blocked("IPv4 outbound UDP send", AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                              (struct sockaddr *)&remote4, sizeof(remote4), 2, 0);
    failures += check_blocked("IPv6 loopback bind", AF_INET6, SOCK_STREAM, IPPROTO_TCP,
                              (struct sockaddr *)&loopback6, sizeof(loopback6), 0, 0);
    failures += check_blocked("IPv6 outbound TCP connect", AF_INET6, SOCK_STREAM, IPPROTO_TCP,
                              (struct sockaddr *)&remote6, sizeof(remote6), 1, 1);

    char unique_host[96];
    (void)snprintf(unique_host, sizeof(unique_host), "netless-%lu-%lu.example.com",
                   (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_UNSPEC;
    int dns = getaddrinfo(unique_host, "443", &hints, &result);
    if (dns == 0) {
        fprintf(stderr, "FAIL: DNS lookup for unique external name returned an address\n");
        failures++;
        freeaddrinfo(result);
    }
    failures += test_udp_dns_response();
    failures += test_loopback_delivery();

    SOCKET raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (raw != INVALID_SOCKET) {
        fprintf(stderr, "LIMITATION: raw IPv4 socket creation succeeded\n");
        DWORD timeout = 500;
        (void)setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
        unsigned char echo[8] = {8, 0, 0, 0, 0x4e, 0x4c, 0, 1};
        unsigned int sum = ((unsigned int)echo[0] << 8) | echo[1];
        for (size_t i = 2; i < sizeof(echo); i += 2)
            sum += ((unsigned int)echo[i] << 8) | echo[i + 1];
        sum = (sum & 0xffffu) + (sum >> 16);
        sum = (sum & 0xffffu) + (sum >> 16);
        echo[2] = (unsigned char)(~sum >> 8);
        echo[3] = (unsigned char)(~sum);
        struct sockaddr_in loopback = {0};
        loopback.sin_family = AF_INET;
        loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int sent = sendto(raw, (const char *)echo, sizeof(echo), 0,
                          (struct sockaddr *)&loopback, sizeof(loopback));
        if (sent != SOCKET_ERROR) {
            char response[128];
            struct sockaddr_in from;
            int from_len = sizeof(from);
            if (recvfrom(raw, response, sizeof(response), 0,
                         (struct sockaddr *)&from, &from_len) > 0) {
                fprintf(stderr, "FAIL: raw ICMP loopback received a response\n");
                failures++;
            } else {
                fprintf(stderr, "INFO: raw ICMP send was accepted but no response reached the process\n");
            }
        }
        closesocket(raw);
    }
    return failures;
}

int wmain(int argc, wchar_t **argv) {
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return 10;
    int failed = probe();
    if (argc == 1) {
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
