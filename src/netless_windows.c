#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <winsock2.h>
#include <windows.h>
#include <userenv.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ws2_32.lib")

static void print_error(const wchar_t *what, DWORD error) {
    fwprintf(stderr, L"netless: %ls failed (Windows error %lu)\n", what, (unsigned long)error);
}

static wchar_t *quote_arg(const wchar_t *arg) {
    size_t cap = wcslen(arg) * 2 + 3;
    wchar_t *out = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*out));
    if (!out) return NULL;
    size_t j = 0;
    out[j++] = L'"';
    size_t slashes = 0;
    for (size_t i = 0;; ++i) {
        wchar_t c = arg[i];
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'"') {
            for (size_t k = 0; k < slashes * 2 + 1; ++k) out[j++] = L'\\';
            out[j++] = L'"';
        } else if (c == L'\0') {
            for (size_t k = 0; k < slashes * 2; ++k) out[j++] = L'\\';
            out[j++] = L'"';
            out[j] = L'\0';
            break;
        } else {
            for (size_t k = 0; k < slashes; ++k) out[j++] = L'\\';
            out[j++] = c;
        }
        slashes = 0;
    }
    return out;
}

static wchar_t *make_command_line(int argc, wchar_t **argv, int start) {
    size_t total = 1;
    wchar_t **quoted = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)(argc - start) * sizeof(*quoted));
    if (!quoted) return NULL;
    for (int i = start; i < argc; ++i) {
        quoted[i - start] = quote_arg(argv[i]);
        if (!quoted[i - start]) goto fail;
        total += wcslen(quoted[i - start]) + 1;
    }
    wchar_t *line = HeapAlloc(GetProcessHeap(), 0, total * sizeof(*line));
    if (!line) goto fail;
    line[0] = L'\0';
    for (int i = start; i < argc; ++i) {
        if (i != start) wcscat_s(line, total, L" ");
        wcscat_s(line, total, quoted[i - start]);
    }
    for (int i = 0; i < argc - start; ++i) HeapFree(GetProcessHeap(), 0, quoted[i]);
    HeapFree(GetProcessHeap(), 0, quoted);
    return line;
fail:
    for (int i = 0; i < argc - start; ++i) if (quoted[i]) HeapFree(GetProcessHeap(), 0, quoted[i]);
    HeapFree(GetProcessHeap(), 0, quoted);
    return NULL;
}

static void close_duplicate(HANDLE h) {
    if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
}

int wmain(void) {
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) { print_error(L"CommandLineToArgvW", GetLastError()); return 125; }
    if (argc > 1 && wcscmp(argv[1], L"--help") == 0) {
        wprintf(L"Usage: netless.exe -- COMMAND [ARG...]\n"
                L"Run COMMAND in a Windows AppContainer without network capabilities.\n"
                L"AppContainer also restricts filesystem, registry, and IPC access.\n");
        LocalFree(argv);
        return 0;
    }
    int sep = 1;
    while (sep < argc && wcscmp(argv[sep], L"--") != 0) ++sep;
    if (sep + 1 >= argc) {
        fwprintf(stderr, L"Usage: netless.exe -- COMMAND [ARG...]\n");
        LocalFree(argv);
        return 2;
    }

    /* Per-invocation identity avoids inheriting any user-configured exemptions. */
    wchar_t profile_name[96];
    (void)swprintf_s(profile_name, 96, L"netless-%lu-%lu", GetCurrentProcessId(), GetTickCount());
    PSID app_sid = NULL;
    HRESULT hr = CreateAppContainerProfile(profile_name, L"netless", L"network-restricted command", NULL, 0, &app_sid);
    if (FAILED(hr)) {
        print_error(L"creating AppContainer profile", HRESULT_CODE(hr));
        LocalFree(argv);
        return 125;
    }

    SECURITY_CAPABILITIES caps = {0};
    caps.AppContainerSid = app_sid;
    STARTUPINFOEXW sx = {0};
    sx.StartupInfo.cb = sizeof(sx);
    sx.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    HANDLE std_handles[3] = {0};
    BOOL handles_ok = TRUE;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) handles_ok = FALSE;
    for (int i = 0; i < 3; ++i) {
        if (!handles_ok) break;
        HANDLE original = GetStdHandle(i == 0 ? STD_INPUT_HANDLE : i == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        if (!original || original == INVALID_HANDLE_VALUE) { std_handles[i] = NULL; continue; }
        int socket_type = 0;
        int socket_type_len = sizeof(socket_type);
        if (getsockopt((SOCKET)(uintptr_t)original, SOL_SOCKET, SO_TYPE,
                       (char *)&socket_type, &socket_type_len) == 0) {
            fwprintf(stderr, L"netless: refusing inherited socket on standard handle %d\n", i);
            handles_ok = FALSE;
            break;
        }
        if (!DuplicateHandle(GetCurrentProcess(), original, GetCurrentProcess(), &std_handles[i], 0, TRUE, DUPLICATE_SAME_ACCESS)) {
            handles_ok = FALSE;
            break;
        }
    }
    sx.StartupInfo.hStdInput = std_handles[0];
    sx.StartupInfo.hStdOutput = std_handles[1];
    sx.StartupInfo.hStdError = std_handles[2];
    SIZE_T attr_size = 0;
    (void)InitializeProcThreadAttributeList(NULL, 2, 0, &attr_size);
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = HeapAlloc(GetProcessHeap(), 0, attr_size);
    if (!handles_ok || !attrs || !InitializeProcThreadAttributeList(attrs, 2, 0, &attr_size)) {
        print_error(L"preparing restricted process", GetLastError());
        for (int i = 0; i < 3; ++i) close_duplicate(std_handles[i]);
        if (attrs) HeapFree(GetProcessHeap(), 0, attrs);
        WSACleanup();
        DeleteAppContainerProfile(profile_name);
        FreeSid(app_sid);
        LocalFree(argv);
        return 125;
    }
    sx.lpAttributeList = attrs;
    HANDLE inherited[3];
    DWORD inherited_count = 0;
    for (int i = 0; i < 3; ++i) if (std_handles[i]) inherited[inherited_count++] = std_handles[i];
    BOOL attr_ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                             &caps, sizeof(caps), NULL, NULL);
    if (attr_ok && inherited_count)
        attr_ok = UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                            inherited, inherited_count * sizeof(HANDLE), NULL, NULL);
    wchar_t *command_line = make_command_line(argc, argv, sep + 1);
    PROCESS_INFORMATION pi = {0};
    BOOL created = FALSE;
    if (attr_ok && command_line) {
        created = CreateProcessW(NULL, command_line, NULL, NULL, inherited_count != 0,
                                 EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
                                 &sx.StartupInfo, &pi);
    }
    DWORD create_error = GetLastError();
    if (!created) print_error(L"launching AppContainer process", create_error);
    for (int i = 0; i < 3; ++i) close_duplicate(std_handles[i]);
    if (command_line) HeapFree(GetProcessHeap(), 0, command_line);
    DeleteProcThreadAttributeList(attrs);
    HeapFree(GetProcessHeap(), 0, attrs);
    FreeSid(app_sid);
    LocalFree(argv);
    WSACleanup();
    if (!created) { DeleteAppContainerProfile(profile_name); return 125; }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD status = 125;
    (void)GetExitCodeProcess(pi.hProcess, &status);
    CloseHandle(pi.hProcess);
    (void)DeleteAppContainerProfile(profile_name);
    return (int)status;
}
