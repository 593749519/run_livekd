#include <iostream>
#include <windows.h>
#include <sddl.h>

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool CreateProcessWithDebugPrivilege(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, STARTUPINFO& si, PROCESS_INFORMATION& pi) {
    HANDLE hToken;
    HANDLE hNewToken;
    LUID luid;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!DuplicateTokenEx(hToken, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        std::cerr << "DuplicateTokenEx failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hNewToken);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hNewToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        CloseHandle(hNewToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        CloseHandle(hToken);
        CloseHandle(hNewToken);
        return false;
    }

    CloseHandle(hToken);

    if (!CreateProcessAsUserW(hNewToken, lpApplicationName, lpCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "CreateProcessAsUserW failed: " << GetLastError() << std::endl;
        CloseHandle(hNewToken);
        return false;
    }

    CloseHandle(hNewToken);
    return true;
}

int main(int argc, char* argv[]) 
{
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return 1;
    }

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
  
    wchar_t szArgv[MAX_PATH] = { 0 };
    if (argc < 2)
    {
        mbstowcs(szArgv, "c:\\symbols", strlen("c:\\symbols"));
    }
    else
    {
        mbstowcs(szArgv, argv[1], strlen(argv[1]));
    }

    wchar_t szCmdline[MAX_PATH] = { 0 };
    swprintf_s(szCmdline, _countof(szCmdline), L"livekd64.exe -y srv*%s*https://msdl.microsoft.com/download/symbols", szArgv);

    if (CreateProcessWithDebugPrivilege(NULL, szCmdline, si, pi)) {
        std::cout << "Process created with debug privilege." << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cerr << "Failed to create process." << std::endl;
        return 1;
    }

    return 0;
}