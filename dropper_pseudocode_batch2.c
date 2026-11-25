// ============================================================================
// WannaCry Dropper (WannaCry.exe) - Batch 2: AES, Minizip, Helpers
// SHA256 : be22645c61949ad6a077373a7d6cd85e3fae44315632f161adc4c99d5a8e6844
// IDA DB : 442b9b2d216f
// ----------------------------------------------------------------------------
// ANALYSIS ARTIFACT - readability render only. Cryptographic cores are
// described, not implemented (no working AES/minizip code supplied).
// ============================================================================

#include <windows.h>

// ============================================================================
// AES-128/192/256 context layout (as consumed by sub_40224E)
// ============================================================================
//  +8     enc round keys    (11/13/15 * 16 bytes)
//  +488   dec round keys
//  +968   key length        (16 / 24 / 32)
//  +972   block size        (16)
//  +1008  IV                (16 bytes)
//  +1040  rounds            (10 / 12 / 14)
//  +1044  temp buffer
typedef struct AesContext {
    BYTE   encKeys[15 * 16];   // +8
    BYTE   decKeys[15 * 16];   // +488
    // ... remainder as anonymous byte storage at the fixed offsets above
} AesContext;

// S-box: byte_408994[256] (standard AES)
// Te tables (fast encryption T-tables):
//   dword_40AB94[256] = Te0
//   dword_40AF94[256] = Te1
//   dword_40B394[256] = Te2
//   dword_40B794[256] = Te3

// ----------------------------------------------------------------------------
// sub_40224E  AES key expansion
//   16/24/32-byte key, 16-byte block; rounds 10/12/14.
//   Produces encryption and decryption round keys.
// sub_402656  encrypt round #1  (Te0..Te3)
// sub_402994  encrypt round #2
// sub_402CE7  full block encrypt
// sub_402F6F  full block decrypt
// sub_403200  XOR 16-byte blocks
// ----------------------------------------------------------------------------

// ============================================================================
// sub_40324F - AES mode driver
// ============================================================================
void __cdecl sub_40324F(void *ctx, void *data, int len, int mode)
{
    AesContext *aes = (AesContext *)ctx;
    BYTE *buf = (BYTE *)data;
    BYTE  iv[16];

    memcpy(iv, (BYTE *)ctx + 1008, 16);

    for (int i = 0; i < len; i += 16) {
        switch (mode) {
        case 1: {                               // CBC decrypt
            sub_402F6F(aes, buf + i, buf + i);  // decrypt in place
            sub_403200(buf + i, iv, 16);        // ^ IV
            memcpy(iv, buf + i, 16);            // IV = ciphertext
            break;
        }
        case 2: {                               // CFB
            BYTE keystream[16];
            sub_402CE7(aes, iv, keystream);     // E(IV)
            sub_403200(buf + i, keystream, 16); // ^ keystream
            memcpy(iv, buf + i, 16);            // IV = ciphertext
            break;
        }
        default:                                // ECB decrypt
            sub_402F6F(aes, buf + i, buf + i);
            break;
        }
    }
    memcpy((BYTE *)ctx + 1008, iv, 16);
}

// ============================================================================
// zlib / minizip cluster
// ----------------------------------------------------------------------------
// sub_4034D4  inflate() wrapper (10-case switch, jumptable 0x40351F) —
//             standard zlib 1.1.3 inflate; calls sub_4048FA, sub_4034A0,
//             sub_4033AE, memcpy, sub_404778, sub_4047F7
// sub_403B8E  unzip/minizip core (~2000 bytes, jumptable 0x403BE0) —
//             central-directory parsing, PKZIP decrypt, entry extraction
// ============================================================================

// ============================================================================
// File / time helpers
// ----------------------------------------------------------------------------
// sub_4043F1  file-time conversion / comparison
// sub_404925  path / filename manipulation
// sub_405014  FindFirstFile / FindNextFile iteration (14-case switch)
// sub_4059B8  file copy with timestamp preservation
// sub_406418  directory traversal / file enumeration
// sub_40690E  file write with timestamp preservation
// ============================================================================

// ============================================================================
// Minizip wrappers
// ----------------------------------------------------------------------------
// sub_406C53  unzOpen wrapper
// sub_406C7C  unzOpen2, memory mode (3); returns 0x244-byte unzFile struct
// sub_406D85  (data, size, pw) -> sub_406C7C(data, size, 3, pw)
// sub_406D9C  unzGetCurrentFileInfo wrapper
// sub_406E15  unzOpenCurrentFilePassword / unzReadCurrentFile wrapper
// sub_406E2E  unzClose wrapper
// ============================================================================

// ============================================================================
// Embedded RSA-2048 private key (@0x40EB38 / file offset 0xEB38, 1172 bytes)
// ----------------------------------------------------------------------------
// PRIVATEKEYBLOB layout:
//   BLOBHEADER : bType=7 (PRIVATEKEYBLOB), bVersion=2, aiKeyAlg=0xA400 (CALG_RSA_KEYX)
//   RSAPUBKEY  : magic="RSA2", bitlen=2048, pubexp=65537
//   n   @ 20   (256 bytes, LE)   modulus
//   p   @ 276  (128 bytes)       prime1
//   q   @ 404  (128 bytes)       prime2
//   dp  @ 532  (128 bytes)       d mod (p-1)
//   dq  @ 660  (128 bytes)       d mod (q-1)
//   iq  @ 788  (128 bytes)       q^-1 mod p
//   d   @ 916  (256 bytes)       private exponent
// Verified: p*q == n and pow(pow(2,65537,n),d,n) == 2
// ============================================================================

// ============================================================================
// SMD resource ZIP (ID 105, type "SMD")
// ----------------------------------------------------------------------------
// Offset 65776, size 160287
// SHA256 ba3e1d91654bdd3dc10334db8f2685c03251e1fae1538e39acf6ae520175d983
// 5 entries, traditional PKZIP encrypted (flag 0x0001):
//   c.wry  method 8  csize 106    usize 628     crc 0x3283206e  config
//   m.wry  method 8  csize 9242   usize 43832   crc 0x90fe7ab9  RTF ransom note
//   r.wry  method 8  csize 426    usize 729     crc 0xc2089774  Q&A template
//   t.wry  method 0  csize 69924  usize 69912   crc 0x1d0c9f86  WANNACRY -> payload.dll
//   u.wry  method 8  csize 79957  usize 241664  crc 0x7ea9837d  decryptor -> u.dll
// Password "wcry@2016"
// ============================================================================

// ============================================================================
// Decrypted artifacts
// ----------------------------------------------------------------------------
// t.wry -> payload.dll : 69632 bytes, PE32, imagebase 0x10000000, EP rva 0x71af
//                        export StartTask @ rva 0xCE90
//                        imports KERNEL32 USER32 ADVAPI32 SHELL32 WS2_32
//                                NETAPI32 MPR MSVCRT MSVCP60
// u.wry -> u.dll       : 241664 bytes, PE32, imagebase 0x400000, EP rva 0x12568
//                        no exports, MFC dialog app, large .rsrc
// ============================================================================

// ============================================================================
// Configuration (c.wry - 628 bytes)
// ----------------------------------------------------------------------------
//   0x00 : DWORD = 0
//   0x04 : DWORD = 1
//   0x60 : DWORD = 3
//   0x64 : DWORD = 7
//   0x68 : float = 300.0 (0x43960000)   ransom $300
//   0x80 : "15zGqZCTcys6eCjDkE3DypCjXi6QWRV6V1"   BTC address
//   0xC0 : "sqjolphimrr7jqw6.onion"              Tor hidden service
//   rest : zero
// ============================================================================
