// ============================================================================
// WannaCry Decryptor GUI (u.dll) - key functions
// SHA256 : 78e3f87f31688355c0f398317b2d87d803bd87ee3656c5a7c80f0561ec8606df
// IDA DB : aa3efcf9b186
// Type   : MFC dialog app, 576 functions, 241664 bytes, imagebase 0x400000
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render. Not buildable.
// ============================================================================

#include <windows.h>
#include <winsock2.h>
#include <winnetwk.h>

// ============================================================================
// sub_401710 - OnDestroy / cleanup
// ----------------------------------------------------------------------------
// Reads %08X.dky. If present -> success message. Otherwise drives the payment
// state machine (1 = wait for .dky, -1 = payment failed, 2 = success) and
// cleans up threads, handles and temp files.
// ============================================================================
void __cdecl sub_401710(void)
{
    WaitForSingleObject(hThread, INFINITE);
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    DeleteFileA("temp_file");
}

// ============================================================================
// sub_401B20 - SMB connection (inet_ntoa)
// ============================================================================
int __cdecl sub_401B20(struct in_addr in)
{
    char *ip_str = inet_ntoa(in);                   // format for WNetAddConnection2
    (void)ip_str;
    // ... SMB connection via WNetAddConnection2
    return 0;
}

// ============================================================================
// sub_401B60 - SMB authentication
// ============================================================================
int __cdecl sub_401B60(NETRESOURCE *nr, char *user, char *pass, BOOL force)
{
    (void)force;
    return WNetAddConnection2(nr, pass, user, 0);
}

// ============================================================================
// sub_4020F0 - init crypto context + two 1 MB buffers
// ----------------------------------------------------------------------------
// Same shape as dropper sub_401000; sub_404B30 AcquireContext; loads RSA private
// key from .dky or embedded; allocates two 1 MB buffers at this+306, this+307.
// ============================================================================
int __thiscall sub_4020F0(void *this, const char *key_file)
{
    (void)this; (void)key_file;
    return 1;
}

// ============================================================================
// sub_402170 - decrypt one file (core)
// ----------------------------------------------------------------------------
// Header: "WANNACRY"(8) + BYTE[256] rsa_blob + DWORD mode(3|4) + QWORD orig_size
//  1. RSA-decrypt AES key via sub_404F30 (CryptDecrypt Final=TRUE)
//  2. AES key schedule via sub_40A2D0(this, key, 16, 16)
//  3. mode 3: decrypt last 64 KB in place (sub_40B540)
//     mode 4: create .dec output, decrypt 1 MB chunks (sub_40B540), MoveFileW over original
//  4. restore timestamps; close handles
// ============================================================================
int __thiscall sub_402170(void *this, const wchar_t *encrypted_file)
{
    (void)this; (void)encrypted_file;
    return 1;
}

// ============================================================================
// sub_4039F0 - main dialog / list-selection handler
// ============================================================================
LRESULT __stdcall sub_4039F0(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch (Msg) {
    case WM_COMMAND:
        // list selection -> check .dky -> payment dialog -> SMB connect
        // -> spawn decrypt worker: CreateThread(NULL, 0, sub_403CF0, ...)
        break;
    case WM_TIMER:
        // periodic checks
        break;
    }
    return DefWindowProc(hWnd, Msg, wParam, lParam);
}

// ============================================================================
// sub_403CF0 - decrypt worker thread entry
// ============================================================================
DWORD WINAPI sub_403CF0(LPVOID lpParameter)
{
    sub_403D00(lpParameter);
    return 0;
}

// ============================================================================
// sub_403D00 - decrypt worker main loop
// ----------------------------------------------------------------------------
// Init crypto (sub_4020F0), enumerate f.wry (UTF-8 lines) via sub_403F30,
// decrypt each via sub_402170, update UI progress.
// ============================================================================
void __cdecl sub_403D00(void *arg)
{
    (void)arg;
}

// ============================================================================
// sub_403E30 - target selection
// ============================================================================
void __cdecl sub_403E30(int payment_host_ip)
{
    if (payment_host_ip) {
        sub_401B20(payment_host_ip);                // targeted: connect to payment host
    } else {
        // enumerate fixed drives (GetLogicalDrives, GetDiskFreeSpaceExW) and
        // process f.wry entries on each
    }
}

// ============================================================================
// sub_403F30 - enumerate f.wry lines
// ----------------------------------------------------------------------------
// fopen f.wry (UTF-8 text, one path per line); for each line call sub_402170.
// ============================================================================
void __cdecl sub_403F30(void *this, const char *f_wry_path)
{
    (void)this; (void)f_wry_path;
}

// ============================================================================
// sub_404F30 - RSA decrypt (CryptoAPI)
// ============================================================================
int __thiscall sub_404F30(void *this, BYTE *pbData, DWORD pdwDataLen,
                          BYTE *out, DWORD *out_len)
{
    if (!*(HCRYPTKEY *)((char *)this + 8))
        return 0;

    EnterCriticalSection((LPCRITICAL_SECTION)((char *)this + 16));
    BOOL ok = CryptDecrypt(*(HCRYPTKEY *)((char *)this + 8), 0, TRUE, 0, pbData, &pdwDataLen);
    LeaveCriticalSection((LPCRITICAL_SECTION)((char *)this + 16));

    if (ok) {
        memcpy(out, pbData, pdwDataLen);
        *out_len = pdwDataLen;
        return 1;
    }
    return 0;
}

// ============================================================================
// sub_40A2D0 - AES key schedule (C++ class with exception throws)
// ----------------------------------------------------------------------------
// Same as dropper sub_40224E. Layout: +968 key_len, +972 block_size, +976 orig IV,
// +1008 IV, +1040 rounds, +1044 temp, +8 enc keys, +488 dec keys.
// S-box byte_416078.
// ============================================================================
int __thiscall sub_40A2D0(void *this, int key_ptr, int key_len, int block_size)
{
    char *p = (char *)this;

    if (key_len != 16 && key_len != 24 && key_len != 32)
        throw /* invalid key length */ 0;
    if (block_size != 16 && block_size != 24 && block_size != 32)
        throw /* invalid block size */ 0;

    *(DWORD *)(p + 968) = key_len;
    *(DWORD *)(p + 972) = block_size;
    memcpy(p + 976, (void *)key_ptr, key_len);
    memcpy(p + 1008, (void *)key_ptr, block_size);  // IV = first block_size bytes of key

    int rounds;
    if (key_len == 16)      rounds = (block_size == 16) ? 10 : (block_size == 24 ? 12 : 14);
    else if (key_len == 24) rounds = (block_size == 32) ? 14 : 12;
    else                    rounds = 14;
    *(DWORD *)(p + 1040) = rounds;

    // zero round-key buffers, then standard AES key expansion using S-box byte_416078
    return 1;
}

// sub_40A2C0 - AES encrypt block
// sub_40A290 - AES decrypt block

// ============================================================================
// sub_40B540 - AES-CBC decrypt driver
// ----------------------------------------------------------------------------
// For each 16-byte block: decrypt in place, XOR with IV (this+1008), IV = cipher.
// ============================================================================
int __thiscall sub_40B540(void *this, BYTE *data, int len)
{
    for (int i = 0; i < len; i += 16) {
        sub_40A290(this, data + i, data + i);       // decrypt block
        for (int k = 0; k < 16; ++k)                // XOR 16 with IV
            data[i + k] ^= *((BYTE *)this + 1008 + k);
        memcpy((BYTE *)this + 1008, data + i, 16);  // IV = ciphertext
    }
    return 1;
}

// ============================================================================
// sub_404BB0 - crypto context cleanup
// ============================================================================
int __thiscall sub_404BB0(void *this)
{
    if (*(HCRYPTKEY *)((char *)this + 8))
        CryptDestroyKey(*(HCRYPTKEY *)((char *)this + 8));
    if (*(HCRYPTPROV *)((char *)this + 4))
        CryptReleaseContext(*(HCRYPTPROV *)((char *)this + 4), 0);
    return 1;
}

// ============================================================================
// File formats (decryptor side)
// ----------------------------------------------------------------------------
// f.wry : UTF-8 text, one encrypted file path per line
// .dky  : recovery key (RSA private key blob); if present -> auto-decrypt
// .pky  : public key
// .eky  : encrypted private key
// .res  : state / resume file
// ============================================================================

// ============================================================================
// Payment / decrypt flow
// ----------------------------------------------------------------------------
// 1. run u.dll (dropped as @WanaDecryptor@.exe + .lnk shortcut)
// 2. dialog lists encrypted files from f.wry
// 3. user selects file, clicks Decrypt
// 4. if .dky exists -> decrypt immediately
// 5. else show payment dialog, connect to payment host via SMB
// 6. on verification receive .dky, decrypt all files via worker thread
// 7. decrypt each via sub_402170 (mode 3 or 4)
// 8. replace encrypted file with decrypted (MoveFileW)
// ============================================================================
