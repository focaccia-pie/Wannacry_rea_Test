// WannaCry Dropper (WannaCry.exe) - Batch 2: AES, Minizip, Helpers
// SHA256: be22645c61949ad6a077373a7d6cd85e3fae44315632f161adc4c99d5a8e6844
// IDA Database: 442b9b2d216f

// ============================================================================
// AES Implementation Details
// ============================================================================

// AES Key Schedule State (per sub_40224E):
// this+8      = encryption round keys (11*16=176 for AES-128)
// this+488    = decryption round keys
// this+968    = key length (16/24/32)
// this+972    = block size (16)
// this+1008   = IV (16 bytes)
// this+1040   = number of rounds (10/12/14)
// this+1044   = temp buffer

// S-box: byte_408994[256] (standard AES S-box)
// Te tables (T-tables for fast encryption):
// dword_40AB94[256] = Te0
// dword_40AF94[256] = Te1
// dword_40B394[256] = Te2
// dword_40B794[256] = Te3

// sub_40224E - AES Key Expansion
// Accepts key_len 16/24/32, block_size 16
// Rounds: 10 (AES-128), 12 (AES-192), 14 (AES-256)
// Generates both encryption and decryption round keys

// sub_402656 - AES Encrypt Round Function 1 (Te0/Te1/Te2/Te3 based)
// sub_402994 - AES Encrypt Round Function 2
// sub_402CE7 - AES Encrypt Block (full encryption)
// sub_402F6F - AES Decrypt Block (full decryption)
// sub_403200 - XOR 16-byte blocks (for CBC/CFB chaining)

// ============================================================================
// sub_40324F - AES Mode Driver
// ============================================================================
void __cdecl sub_40324F(void *ctx, void *data, int len, int mode)
{
  // mode == 1: CBC Decrypt
  //   For each block: decrypt_block(block) ^ IV; IV = ciphertext_block
  // mode == 2: CFB
  //   For each block: encrypt_block(IV) ^ plaintext = ciphertext; IV = ciphertext
  // else: ECB Decrypt
  //   For each block: decrypt_block(block)

  AES_CTX *aes = (AES_CTX *)ctx;
  BYTE *buf = (BYTE *)data;
  BYTE iv[16];
  memcpy(iv, aes->iv, 16);

  for (int i = 0; i < len; i += 16) {
    if (mode == 1) {  // CBC Decrypt
      sub_402F6F(aes, buf + i, buf + i);  // decrypt in-place
      sub_403200(buf + i, iv, 16);        // XOR with IV
      memcpy(iv, buf + i, 16);            // IV = ciphertext
    } else if (mode == 2) {  // CFB
      BYTE keystream[16];
      sub_402CE7(aes, iv, keystream);     // encrypt IV
      sub_403200(buf + i, keystream, 16); // XOR with keystream
      memcpy(iv, buf + i, 16);            // IV = ciphertext
    } else {  // ECB Decrypt
      sub_402F6F(aes, buf + i, buf + i);
    }
  }
  memcpy(aes->iv, iv, 16);
}

// ============================================================================
// zlib/minizip Cluster (sub_4034D4, sub_403B8E)
// ============================================================================
// sub_4034D4 - inflate() wrapper (10-case switch jumptable 0x40351F)
// Calls: sub_4048FA, sub_4034A0, sub_4033AE, memcpy, sub_404778, sub_4047F7
// Standard zlib 1.1.3 inflate implementation

// sub_403B8E - unzip/minizip core (10-case switch jumptable 0x403BE0, ~2000 bytes)
// Calls: sub_4048FA, sub_4034D4, sub_4033AE, sub_403A87, sub_404778, sub_4047F7
// Central directory parsing, PKZIP decryption, entry extraction
// Time budget exhausted - partial analysis

// ============================================================================
// File/Time Helpers
// ============================================================================

// sub_4043F1 - File time conversion / comparison (7 runs)
// sub_404925 - Path/filename manipulation (4 runs)
// sub_405014 - File find/iteration (14-case switch, FindFirstFile/FindNextFile)
// sub_4059B8 - File copy with time preservation (SetFileTime, LocalFileTimeToFileTime)
// sub_406418 - Directory traversal / file enumeration
// sub_40690E - File write with timestamp preservation (CreateFileA, WriteFile, SetFileTime, CloseHandle)
// STATUS: COMPLETE

// ============================================================================
// Minizip Wrappers (Complete)
// ============================================================================

// sub_406C53 - unzOpen wrapper (memory mode preparation)
// sub_406C7C - unzOpen2 / unzOpen memory mode (3)
//   Opens ZIP from memory buffer, mode 3 = memory
//   Returns 0x244-byte unzFile struct with password storage
// sub_406D85(data, size, password) -> sub_406C7C(data, size, 3, password)
//   Entry point for SMD resource extraction
// sub_406D9C - unzGetCurrentFileInfo wrapper
// sub_406E15 - unzOpenCurrentFilePassword / unzReadCurrentFile wrapper
//   Extracts single entry with traditional PKZIP encryption
// sub_406E2E - unzClose wrapper
// STATUS: COMPLETE

// ============================================================================
// Embedded RSA-2048 Private Key (at 0x40EB38, file offset 0xEB38)
// ============================================================================
// PRIVATEKEYBLOB (1172 bytes):
//   BLOBHEADER: bType=7(PRIVATEKEYBLOB), bVersion=2, reserved=0, aiKeyAlg=0xA400(CALG_RSA_KEYX)
//   RSAPUBKEY: magic="RSA2", bitlen=2048, pubexp=65537
//   Modulus n (256 bytes, LE) at offset 20
//   Prime p (128 bytes) at offset 276
//   Prime q (128 bytes) at offset 404
//   d mod (p-1) (128 bytes) at offset 532
//   d mod (q-1) (128 bytes) at offset 660
//   q^-1 mod p (128 bytes) at offset 788
//   Private exponent d (256 bytes) at offset 916
// Verified: p*q == n, pow(pow(2,65537,n),d,n) == 2

// ============================================================================
// SMD Resource ZIP (ID 105, type "SMD")
// ============================================================================
// Offset 65776, Size 160287, SHA256: ba3e1d91654bdd3dc10334db8f2685c03251e1fae1538e39acf6ae520175d983
// 5 entries, all traditional PKZIP encrypted (flags=0x0001):
//   c.wry   method=8 csize=106   usize=628   crc=0x3283206e  (CONFIG)
//   m.wry   method=8 csize=9242  usize=43832 crc=0x90fe7ab9  (RTF ransom note)
//   r.wry   method=8 csize=426   usize=729   crc=0xc2089774  (Q&A template)
//   t.wry   method=0 csize=69924 usize=69912 crc=0x1d0c9f86  (WANNACRY container -> payload.dll)
//   u.wry   method=8 csize=79957 usize=241664 crc=0x7ea9837d (decryptor GUI -> u.dll)
// Password: "wcry@2016" (from decoded string at 0x40F304)

// ============================================================================
// Decrypted Artifacts
// ============================================================================
// t.wry -> payload.dll (69632 bytes, PE32, imagebase 0x10000000, EP rva 0x71af)
//   Export: StartTask @ rva 0xCE90
//   Sections: .text .rdata .data .rsrc .reloc
//   Imports: KERNEL32 USER32 ADVAPI32 SHELL32 WS2_32 NETAPI32 MPR MSVCRT MSVCP60
// u.wry -> u.dll (241664 bytes, PE32, imagebase 0x400000, EP rva 0x12568)
//   No exports, MFC dialog app, large .rsrc section

// ============================================================================
// Configuration (c.wry - 628 bytes)
// ============================================================================
// DWORDs at 0x0: 0, 1
// DWORDs at 0x60: 3, 7
// Float at 0x68: 300.0 (0x43960000) - ransom $300
// String at 0x80: "15zGqZCTcys6eCjDkE3DypCjXi6QWRV6V1" (Bitcoin address)
// String at 0xC0: "sqjolphimrr7jqw6.onion" (Tor hidden service)
// Rest zeros