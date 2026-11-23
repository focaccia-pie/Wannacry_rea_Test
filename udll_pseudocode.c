// WannaCry Decryptor GUI (u.dll) - Key Functions
// SHA256: 78e3f87f31688355c0f398317b2d87d803bd87ee3656c5a7c80f0561ec8606df
// IDA Database: aa3efcf9b186
// MFC Dialog App, 576 functions, 241664 bytes, imagebase 0x400000

// ============================================================================
// sub_401710 - OnDestroy / Cleanup
// ============================================================================
void __cdecl sub_401710()
{
  // Read %08X.dky (recovery key file)
  // If exists -> show decrypt success message
  // Else -> payment check state machine:
  //   case 1: wait for .dky file
  //   case -1: payment failed
  //   case 2: payment success
  // Cleanup threads, handles, temp files
  WaitForSingleObject(hThread, INFINITE);
  TerminateThread(hThread, 0);
  CloseHandle(hThread);
  // Delete temp files
  DeleteFileA("temp_file");
}

// ============================================================================
// sub_401B20 - SMB Connection (inet_ntoa)
// ============================================================================
int __cdecl sub_401B20(struct in_addr in)
{
  // Convert IP to string for SMB connection
  char *ip_str = inet_ntoa(in);
  // ... SMB connection logic via WNetAddConnection2
  return 0;
}

// ============================================================================
// sub_401B60 - SMB Authentication
// ============================================================================
int __cdecl sub_401B60(NETRESOURCE *nr, char *user, char *pass, BOOL force)
{
  // WNetAddConnection2 / WNetCancelConnection2
  // Authenticate to payment/target host
  return WNetAddConnection2(nr, pass, user, 0);
}

// ============================================================================
// sub_4020F0 - Init Crypto Context + 1MB Buffers
// ============================================================================
int __thiscall sub_4020F0(void *this, const char *key_file)
{
  // Initialize crypto context (similar to dropper's sub_401000)
  // sub_404B30 - CryptoAPI acquire context
  // Allocate two 1MB buffers at this+306, this+307
  // Load RSA private key from .dky or embedded
  return 1;
}

// ============================================================================
// sub_402170 - DECRYPT ONE FILE (Core decryption routine)
// ============================================================================
int __thiscall sub_402170(void *this, const wchar_t *encrypted_file)
{
  // 1. Open encrypted file (CreateFileW)
  // 2. Read WANNACRY header:
  //    - "WANNACRY" magic (8 bytes)
  //    - RSA-encrypted AES key (256 bytes)
  //    - Mode (DWORD): 3 or 4
  //    - Original size (QWORD)
  //
  // 3. RSA Decrypt AES key via sub_404F30 (CryptDecrypt with Final=TRUE)
  //    EnterCriticalSection(this+16)
  //    CryptDecrypt(hKey=this+8, 0, TRUE, 0, rsa_blob, &len)
  //    LeaveCriticalSection
  //
  // 4. AES Key Schedule via sub_40A2D0(this, key, keylen, blocksize=16)
  //
  // 5. Decrypt based on mode:
  //    Mode 3 (small file, v11==3):
  //      - Decrypt last 64KB in-place (overwrite)
  //      - sub_40B540 (AES-CBC decrypt) on last chunk
  //    Mode 4 (large file):
  //      - Create .dec output file
  //      - Decrypt 1MB chunks via AES-CBC (sub_40B540)
  //      - MoveFileW replace original with .dec
  //
  // 6. Restore timestamps (GetFileTime/SetFileTime)
  // 7. Close handles
  return 1;
}

// ============================================================================
// sub_4039F0 - Main Dialog / List Selection Handler
// ============================================================================
LRESULT __stdcall sub_4039F0(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  switch (Msg) {
    case WM_COMMAND:
      // List selection -> check .dky file exists
      // Show payment dialog
      // SMB connect via sub_401B20/sub_401B60
      // Spawn decrypt worker thread: CreateThread(NULL, 0, sub_403CF0, ...)
      break;
    case WM_TIMER:
      // Periodic checks
      break;
  }
  return DefWindowProc(hWnd, Msg, wParam, lParam);
}

// ============================================================================
// sub_403CF0 - Decrypt Worker Thread Entry
// ============================================================================
DWORD WINAPI sub_403CF0(LPVOID lpParameter)
{
  sub_403D00(lpParameter);
  return 0;
}

// ============================================================================
// sub_403D00 - Decrypt Worker Main Loop
// ============================================================================
void __cdecl sub_403D00(void *arg)
{
  // 1. Initialize crypto: sub_4020F0(this, key_file)
  // 2. Enumerate f.wry file list (UTF-8 lines) via sub_403F30
  // 3. For each file in list:
  //      sub_402170(this, file_path)
  // 4. Update UI progress
}

// ============================================================================
// sub_403E30 - Target Selection
// ============================================================================
void __cdecl sub_403E30(int payment_host_ip)
{
  if (payment_host_ip) {
    // Targeted mode: connect to payment host via sub_401B20
    sub_401B20(payment_host_ip);
  } else {
    // Enumerate all fixed drives (GetLogicalDrives, GetDiskFreeSpaceExW)
    // For each drive: process f.wry entries on that drive
  }
}

// ============================================================================
// sub_403F30 - Enumerate f.wry Lines
// ============================================================================
void __cdecl sub_403F30(void *this, const char *f_wry_path)
{
  // fopen f.wry (UTF-8 text file, one path per line)
  // For each line: call sub_402170(this, line)
  // fclose
}

// ============================================================================
// sub_404F30 - RSA Decrypt (CryptoAPI)
// ============================================================================
int __thiscall sub_404F30(void *this, BYTE *pbData, DWORD pdwDataLen, BYTE *out, DWORD *out_len)
{
  // this+8 = HCRYPTKEY (RSA private key)
  // this+16 = CRITICAL_SECTION
  if (!*(HCRYPTKEY *)(this + 8)) return 0;

  EnterCriticalSection((LPCRITICAL_SECTION)(this + 16));
  BOOL ok = CryptDecrypt(*(HCRYPTKEY *)(this + 8), 0, TRUE, 0, pbData, &pdwDataLen);
  if (ok) {
    LeaveCriticalSection((LPCRITICAL_SECTION)(this + 16));
    memcpy(out, pbData, pdwDataLen);
    *out_len = pdwDataLen;
    return 1;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(this + 16));
  return 0;
}

// ============================================================================
// sub_40A2D0 - AES Key Schedule (C++ class with exception handling)
// ============================================================================
// Identical to dropper's sub_40224E but with C++ exception throws
// this+968 = key_len (16/24/32)
// this+972 = block_size (16)
// this+1008 = IV (16 bytes)
// this+1040 = rounds (10/12/14)
// this+1044 = temp buffer
// this+8 = encryption round keys
// this+488 = decryption round keys
//
// S-box: byte_416078 (at 0x416078)
// Te tables: similar to dropper
int __thiscall sub_40A2D0(void *this, int key_ptr, int key_len, int block_size)
{
  if (key_len != 16 && key_len != 24 && key_len != 32) throw exception();
  if (block_size != 16 && block_size != 24 && block_size != 32) throw exception();

  *(DWORD *)(this + 968) = key_len;
  *(DWORD *)(this + 972) = block_size;
  memcpy(this + 976, key_ptr, key_len);
  memcpy(this + 1008, key_ptr, block_size);  // IV = first block_size bytes of key

  // Determine rounds
  if (key_len == 16) rounds = (block_size == 16) ? 10 : (block_size == 24 ? 12 : 14);
  else if (key_len == 24) rounds = (block_size == 32) ? 14 : 12;
  else rounds = 14;
  *(DWORD *)(this + 1040) = rounds;

  // Zero round key buffers
  // Key expansion using S-box byte_416078
  // ... standard AES key schedule
  return 1;
}

// sub_40A2C0 - AES Encrypt Block
// sub_40A290 - AES Decrypt Block

// ============================================================================
// sub_40B540 - AES-CBC Decrypt (Driver)
// ============================================================================
// this = AES context (from sub_40A2D0)
// mode: CBC decrypt (sub_40A290 block decrypt + XOR with IV)
// IV updated per block (IV = ciphertext)
int __thiscall sub_40B540(void *this, BYTE *data, int len)
{
  // CBC decrypt loop
  for (int i = 0; i < len; i += 16) {
    sub_40A290(this, data + i, data + i);  // decrypt block
    XOR_16(data + i, this + 1008);          // XOR with IV
    memcpy(this + 1008, data + i, 16);      // IV = ciphertext
  }
  return 1;
}

// ============================================================================
// sub_404BB0 - Crypto Context Cleanup
// ============================================================================
int __thiscall sub_404BB0(void *this)
{
  // Release CryptoAPI key and context
  if (*(HCRYPTKEY *)(this + 8)) {
    CryptDestroyKey(*(HCRYPTKEY *)(this + 8));
  }
  if (*(HCRYPTPROV *)(this + 4)) {
    CryptReleaseContext(*(HCRYPTPROV *)(this + 4), 0);
  }
  return 1;
}

// ============================================================================
// File Formats (Decryptor Side)
// ============================================================================
// f.wry: UTF-8 text file, one encrypted file path per line
// .dky: Recovery key file (RSA private key blob) - if exists, auto-decrypt
// .pky: Public key
// .eky: Encrypted private key
// .res: State/resume file

// ============================================================================
// Payment/Decrypt Flow
// ============================================================================
// 1. User runs u.dll (dropped as @WanaDecryptor@.exe.lnk shortcut)
// 2. Dialog shows encrypted file list (from f.wry)
// 3. User selects file, clicks Decrypt
// 4. Check .dky exists -> if yes, decrypt immediately
// 5. If no .dky: show payment dialog, connect to payment host via SMB
// 6. On payment verification: receive .dky, decrypt files
// 7. Decrypt each file via sub_402170 (mode 3 or 4)
// 8. Replace encrypted file with decrypted (MoveFileW)