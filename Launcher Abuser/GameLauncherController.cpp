
#include "GameLauncherController.h"


GameLauncherController::GameLauncherController(std::wstring launcherName, std::wstring gameProcessName) {
    this->launcherName = launcherName;
    this->gameProcessName = gameProcessName;
}


void GameLauncherController::getLauncherInfo() {
    this->getLauncherHandler();
    
    this->setModuleBaseAddress();
    
    this->findTheCodeCaveOnSectionNullBytes();
}

void GameLauncherController::setModuleBaseAddress() {
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->launcherPid);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);

        if (Module32FirstW(hSnap, &modEntry))
        {
            do
            {
                auto moduleName = std::wstring(modEntry.szModule);
                if (!_wcsnicmp(moduleName.c_str(), this->launcherName.c_str(), this->launcherName.length()))
                {
                    this->launcherMainModuleBaseAddress = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    if (this->launcherMainModuleBaseAddress == NULL)
    {
        notifyErrorAndExit("Something went wrong on the GameLauncherController::setModuleBaseAddress.");
    }
    return; 
}
void GameLauncherController::getLauncherHandler() {
    PROCESSENTRY32W PE32 {
        0
    };
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap == INVALID_HANDLE_VALUE) {
        LogThis(GetLastErrorAsString().c_str());
        notifyErrorAndExit("CreateToolhelp32Snapshot failed!");
        return;
    }

    DWORD PID = 0;
    BOOL bRet = Process32FirstW(hSnap, & PE32);
    while (bRet) {
        if (!wcscmp(PE32.szExeFile, this->launcherName.c_str())) {
          this->launcherPid = PE32.th32ProcessID;
          PID = PE32.th32ProcessID;
          break;
        }

        bRet = Process32NextW(hSnap, &PE32);
    }

    CloseHandle(hSnap);

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->launcherPid);

    if (!processHandle) {
        notifyErrorAndExit("OpenProcess failed");
    }

    this->launcherHandle = processHandle;
    return;    
}

void GameLauncherController::findTheCodeCaveOnSectionNullBytes() {

  IMAGE_DOS_HEADER imageDosHeader = {'\0'};

  ReadProcessMemory(
    this->launcherHandle,
    LPCVOID(this->launcherMainModuleBaseAddress),
    LPVOID(&imageDosHeader),
    sizeof(imageDosHeader),
    NULL
  );

  if ((unsigned short)imageDosHeader.e_magic != 0x5a4d)
  {
    notifyErrorAndExit("Couldnt find the 'MZ' e_magic on IMAGE_DOS_HEADER.");
  }

  IMAGE_NT_HEADERS32 imageNtHeaders = {'\0'};
  
  ReadProcessMemory(
    this->launcherHandle,
    LPCVOID(this->launcherMainModuleBaseAddress + imageDosHeader.e_lfanew),
    LPVOID(&imageNtHeaders),
    sizeof(imageNtHeaders),
    NULL
  );

  // check if PE header is present
  if ((unsigned short)imageNtHeaders.Signature != 0x4550 )
  {
      LogThis((const char*)imageNtHeaders.Signature);
      notifyErrorAndExit("Couldnt find the PE chars on IMAGE_NT_HEADERS signature. Check above.");
  }

  
  if (imageNtHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC )
  {
    notifyErrorAndExit("This aint a 32 bit application. Weird. Check above the Magic.");
  }
  
  PIMAGE_SECTION_HEADER pSectionHeader = PIMAGE_SECTION_HEADER(this->launcherMainModuleBaseAddress + imageDosHeader.e_lfanew + sizeof(DWORD) + sizeof(imageNtHeaders.FileHeader) + imageNtHeaders.FileHeader.SizeOfOptionalHeader);

  for (UINT i = 0; i != imageNtHeaders.FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
    printf("section address %X\n", pSectionHeader);

    IMAGE_SECTION_HEADER sectionHeaderCopy;

    ReadProcessMemory(
      this->launcherHandle,
      LPCVOID(pSectionHeader),
      LPVOID(&sectionHeaderCopy),
      sizeof(sectionHeaderCopy),
      NULL
    );

    // skip if aint an executable section
    if (!(sectionHeaderCopy.Characteristics & IMAGE_SCN_CNT_CODE))
    {
      continue;
    }

      unsigned long sectionTotalSize = NULL;
      // fix this shit
      for (unsigned int i = 1; i < 0x999999999; ++i)
      {
          sectionTotalSize = imageNtHeaders.OptionalHeader.SectionAlignment * i;
          unsigned long total = sectionHeaderCopy.SizeOfRawData/ (sectionTotalSize) ;
          if (total == 0)
          {
            break;
          }
      }      

    if (sectionTotalSize > 0x1000) {
      void * sectionCopyPtr = malloc(sectionTotalSize);
      ReadProcessMemory(
        this->launcherHandle,
        LPCVOID(imageNtHeaders.OptionalHeader.ImageBase + sectionHeaderCopy.VirtualAddress),
        LPVOID(sectionCopyPtr),
        sectionTotalSize,
        NULL
      );

      printf("addres da copia %X\n", sectionCopyPtr);


      BYTE * currentByte = ((BYTE*)sectionCopyPtr + sectionTotalSize);

      while(*currentByte == NULL) {
        currentByte = currentByte-1;
      }

      this->exploitableSectionInfo.numberOfNullBytes = (BYTE*)sectionCopyPtr + sectionTotalSize - currentByte -2;
      this->exploitableSectionInfo.startOfSectionAddr = imageNtHeaders.OptionalHeader.ImageBase + sectionHeaderCopy.VirtualAddress;
      this->exploitableSectionInfo.endOfSectionAddr = this->exploitableSectionInfo.startOfSectionAddr + sectionTotalSize;
      
      free(sectionCopyPtr);
      if (this->exploitableSectionInfo.numberOfNullBytes >= 0x1d0)
      {
        this->exploitableSectionInfo.sectionEndAddress = imageNtHeaders.OptionalHeader.ImageBase + sectionHeaderCopy.VirtualAddress + sectionTotalSize - 1;
        this->exploitableSectionInfo.nullBytesStartAddress = this->exploitableSectionInfo.sectionEndAddress - this->exploitableSectionInfo.numberOfNullBytes ;
        return;
      } else {
        return;  
      }
      
    }
  }

}

void GameLauncherController::overwriteCreateProcessToGetFullAccess(uintptr_t addrOpenProcess, uintptr_t addrOpenProcessJmpTo) {
  void* shellcodeBuffer = VirtualAlloc(NULL, 18, MEM_COMMIT, PAGE_READWRITE);
  
  if (shellcodeBuffer == nullptr) {
    notifyErrorAndExit("shellcodeBuffer == nullptr!");
  };

  SecureZeroMemory(shellcodeBuffer, 18);

  DWORD64 shellcodeBufferEndAddr = (DWORD64)shellcodeBuffer;

  BYTE openProcessWithAllAccessShellcode[] = {

    0xC7,0x44, 0x24, 0x04, 0xFF, 0xFF, 0x1F, 0x0,   // +0x00   | MOV     DWORD PTR SS:[ESP+0x4],0x1FFFFF                  
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,             // +0x8    | JMP     DWORD PTR DS:[<&OpenProcess>]   (TO BE REPLACED)
  };
   
  
  *reinterpret_cast<DWORD*>(openProcessWithAllAccessShellcode + 0xA) = addrOpenProcessJmpTo;

  if (!WriteProcessMemory(this->launcherHandle, (LPVOID)addrOpenProcess, openProcessWithAllAccessShellcode, sizeof(openProcessWithAllAccessShellcode), nullptr))
  {
      notifyErrorAndExit("WriteProcessMemory failed 1!");
  }
}


void GameLauncherController::setupSharedMemory(x86AddressesGrabber::X86FunctionsAddress* x86FunctionsAddress) {

  void* shellcodeBuffer = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);  

  if (shellcodeBuffer == nullptr) {
    notifyErrorAndExit("shellcodeBuffer == nullptr!");
  };

  SecureZeroMemory(shellcodeBuffer, 4096);

  DWORD64 shellcodeBufferEndAddr = (DWORD64)shellcodeBuffer;

  BYTE OpenFileMappingWShellcode[] = {

    // calling OpenFileMappingW 
    0x68, 0x00, 0x00, 0x00, 0x00,      // +0x00  | PUSH lpName address (REPLACE with lpName (c string adress of mappingName))
    0x6A, 0x00,                        // +0x05  | PUSH    0x0 (bInheritHandle)
    0x68, 0x1F, 0x00, 0x0F, 0x00,      // +0x07  | PUSH 0xF001F (dwDesiredAccess)

    0xB8, 0x00,0x00,0x00,0x00,         // +0x0C  | MOV EAX,0x0 (REPLACE OpenFileMappingW function address )
    0xFF, 0xD0,                        // +0x11  | CALL eax
  };
  
  
  DWORD64 lpNameReplaceAddress = (shellcodeBufferEndAddr + 0x01);
  *reinterpret_cast<DWORD*>(OpenFileMappingWShellcode + 0x0D) = x86FunctionsAddress->addrOpenFileMappingWPtr;

  CopyMemory((void*)shellcodeBufferEndAddr, OpenFileMappingWShellcode, sizeof(OpenFileMappingWShellcode));
  shellcodeBufferEndAddr += sizeof(OpenFileMappingWShellcode);

  BYTE MapViewOfFileShellcode[] = {
    // calling MapViewOfFile
    0x50,                                // +0x00 | PUSH    EAX (I'm pushing it here just to save the handle, will need it to call CloseHandle)
    0x68, 0x00, 0x10, 0x00, 0x00,        // +0x01 | PUSH    0x1000      
    0x6A, 0x00,                          // +0x06 | PUSH    0x0        
    0x6A, 0x00,                          // +0x08 | PUSH    0x0       
    0x68, 0x1F, 0x00, 0x0F, 0x00,        // +0x0A | PUSH    0xF001F   
    0x50,                                // +0x0F | PUSH    EAX (it will be the return of OpenFileMappingW)
    0xB8, 0x00,0x00,0x00,0x00,           // +0x10 | MOV EAX,0x0 (REPLACE MapViewOfFile function address )
    0xFF, 0xD0,                          // +0x15 | CALL eax
    0x8B, 0xF0,                          // +0x17 | MOV ESI,EAX (saving the return of MapViewOfFile, which is my filemapping Address)
  };

  *reinterpret_cast<DWORD*>(MapViewOfFileShellcode + 0x11) = x86FunctionsAddress->addrMapViewOfFilePtr;
  CopyMemory((void*)shellcodeBufferEndAddr, MapViewOfFileShellcode, sizeof(MapViewOfFileShellcode));
  shellcodeBufferEndAddr += sizeof(MapViewOfFileShellcode);


  BYTE CloseHandleShellcode[] = {

    //calling CloseHandle (the handle param is already on top of the stack, dont need to push it again)
    0xB8, 0x00,0x00,0x00,0x00,           // +0x00 | MOV EAX,0x0 (REPLACE CloseHandle function address )
    0xFF, 0xD0,                          // +0x05 | CALL eax

  };

  *reinterpret_cast<DWORD*>(CloseHandleShellcode + 0x01) = x86FunctionsAddress->addrCloseHandlePtr;
  CopyMemory((void*)shellcodeBufferEndAddr, CloseHandleShellcode, sizeof(CloseHandleShellcode));
  shellcodeBufferEndAddr += sizeof(CloseHandleShellcode);


  BYTE copySharedMemAddressAndInfiniteLoop[] = {
    0x89, 0x36,       // MOV     DWORD PTR DS:[ESI],ESI (esi has the shared mem address)
    0XEB, 0XFE, // loop infinito
  };

  CopyMemory((void*)shellcodeBufferEndAddr, copySharedMemAddressAndInfiniteLoop, sizeof(copySharedMemAddressAndInfiniteLoop));
  shellcodeBufferEndAddr += sizeof(copySharedMemAddressAndInfiniteLoop);

  DWORD shellcodeSize = (((unsigned int)shellcodeBufferEndAddr) - ((unsigned int)shellcodeBuffer));

  // finding the next aligned address
  DWORD lpNameAddressOnInjectedProcess = this->exploitableSectionInfo.nullBytesStartAddress + shellcodeSize;
  while (lpNameAddressOnInjectedProcess % 8 != 0) {
    lpNameAddressOnInjectedProcess++;
  }

  CopyMemory((void*)lpNameReplaceAddress, (void*)&lpNameAddressOnInjectedProcess, 4 );

  this->launcherHijackingThreadHandler = getThreadHandleBasedOnStartAddress(this->launcherHandle, this->exploitableSectionInfo.startOfSectionAddr, this->exploitableSectionInfo.endOfSectionAddr);

  if (!WriteProcessMemory(this->launcherHandle, (LPVOID)this->exploitableSectionInfo.nullBytesStartAddress, shellcodeBuffer, shellcodeSize, nullptr))
  {
      ResumeThread(this->launcherHijackingThreadHandler);
      notifyErrorAndExit("WriteProcessMemory failed 2");
  }

  std::wstring lpNameFilemappingInjected = L"sharedMe";

  unsigned int sizeOfWCstring = (lpNameFilemappingInjected.size()*2)+2;

  if (!WriteProcessMemory(this->launcherHandle, (LPVOID)lpNameAddressOnInjectedProcess, lpNameFilemappingInjected.c_str(), sizeOfWCstring, nullptr))
  {
      ResumeThread(this->launcherHijackingThreadHandler);
      notifyErrorAndExit("WriteProcessMemory failed 3!");
  }

  HANDLE hLocalSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT | SEC_NOCACHE, 0, sharedMemoBufferSize, (LPCWSTR)lpNameFilemappingInjected.c_str() );
  if (!hLocalSharedMem) {
      notifyErrorAndExit("CreateFileMappingW failed!");
  }
  
  this->sharedMemoryLocalAddress = (DWORD64*)MapViewOfFile(hLocalSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, sharedMemoBufferSize);
  
  if (!this->sharedMemoryLocalAddress) {
      notifyErrorAndExit("MapViewOfFile failed!");
  }  

  ExecWithThreadHiJacking(this->launcherHijackingThreadHandler, this->exploitableSectionInfo.nullBytesStartAddress, shellcodeSize , true);

  this->sharedMemoryInLauncherAddress = *this->sharedMemoryLocalAddress;
  
}



void GameLauncherController::deployControllerShellCode() {

    void* shellcodeBuffer = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE);    

    if (shellcodeBuffer == nullptr) {
      notifyErrorAndExit("shellcodeBuffer == nullptr!");
    };

    SecureZeroMemory(shellcodeBuffer, 4096);

    DWORD64 shellcodeBufferEndAddr = (DWORD64)shellcodeBuffer;

    //0=do nothing, 1=read, 2=write
    BYTE spinlockController[] = {
      0xA0, 0x00, 0x00, 0x00, 0x00,     // +0x00         | MOV     AL,BYTE PTR DS:[sharedMemAddress]
      0x3C, 0x01,                       // +0x05         | CMP     AL,0x1                      
      0x74, 0x04,                       // +0x07         | JE      jumps to NtRVM
      0x72, 0xF5,                       // +0x09         | JB      keeps spinning
      0x7F, 0x00,                       // +0x0b         | JG      jumps to NtWVM
    };

    *reinterpret_cast<DWORD*>(spinlockController + 0x01) = this->sharedMemoryInLauncherAddress;

    CopyMemory((void*)shellcodeBufferEndAddr, spinlockController, sizeof(spinlockController));
    shellcodeBufferEndAddr += sizeof(spinlockController); 

    BYTE ntReadVirtualMemoryx64[] = {

      // heavens gate enter
      0x6A, 0x33,                                          // +0X00  | push 033h ; swap to long mode
      0xE8, 0x00, 0x00, 0x00, 0x00,                        // +0X02  | call $+5
      0x83, 0x04, 0x24, 0x05,                              // +0X07  | add dword ptr [esp], 5
      0xCB,                                                // +0X0B  | retf
      // /heavens gate enter
      // prelogue NtRVM
      0x48, 0x83, 0xEC, 0x28,                              // +0X0C    | sub rsp,28                                                       |
      0x48, 0xA1, 0,0,0,0,0,0,0,0,                         // +0x10    | mov rax,qword ptr ds:[ptr_to_hProcess]
      0x48, 0x8B, 0xC8,                                    // +0x1A    | mov rcx,rax
      0x48, 0xA1, 0,0,0,0,0,0,0,0,                         // +0x1D    | mov rax,qword ptr ds:[ptr_to_lpBaseAddress]
      0x48, 0x8B, 0xD0,                                    // +0x27    | mov rdx,rax
      0x48, 0xA1, 0,0,0,0,0,0,0,0,                         // +0x2A    | mov rax,qword ptr ds:[ptr_to_lpBuffer]
      0x4C, 0x8B, 0xC0,                                    // +0x34    | mov r8,rax
      0x48, 0xA1, 0,0,0,0,0,0,0,0,                         // +0x37    | mov rax,qword ptr ds:[ptr_to_nSize]
      0x4C, 0x8B, 0xC8,                                    // +0x41    | mov r9,rax
      0x48, 0xC7, 0x44, 0x24,  0x28, 0,0,0,0,              // +0x44    | mov qword ptr ss:[rsp+28],0
      // /prelogue NtXVM
      // NtRVM calling block
      0x4C, 0x8B, 0xD1,                                   //  +0X4D    | mov r10,rcx

      0x8A, 0x1C, 0x25, 0x0, 0x0, 0x0, 0x0,                // +0x50    | mov bl,byte ptr ds:[sharedMemAddress]
      0x80, 0xFB,  0x01,                                   // +0x57    | cmp bl,1
      0x7F, 0x07,                                          // +0x5A    | jg ntdll.7FFBD532F9C7
      0xB8, 0x3F, 0x00, 0x00, 0x00,                        // +0X5C    | mov eax,3F //ntReadVirtualMemory
      0xEB, 0x05,                                          // +0X61    | jmp ntdll.7FFBD532F9D3
      0xB8, 0x3A, 0x00, 0x00, 0x00,                        // +0X63    | mov eax,3A // ntWriteVirtualMemory
      0x0F, 0x05,                                          // +0X68    | syscall

      // /NtXVM calling block
      0x48, 0x83, 0xC4, 0x28,                              // +0X6A    | add rsp,28                                                       |
      
      // heavens gate exit
      0xE8, 0x00, 0x00, 0x00, 0x00,                        // +0X6E     | mov r10,rcx
      0xC7, 0x44, 0x24, 0x04, 0x23, 0x00, 0x00, 0x00,      // +0X73     | mov eax,3A
      0x83, 0x04, 0x24, 0x0D, 0xCB,                        // +0X7B     | syscall
      // /heavens gate exit
    };


    SpinLockControlStruct* controlStructInTargetProcess = reinterpret_cast<SpinLockControlStruct*>(this->sharedMemoryInLauncherAddress);
    *reinterpret_cast<HANDLE*>(ntReadVirtualMemoryx64 + 0x12) = &controlStructInTargetProcess->hProcess;
    *reinterpret_cast<DWORD64*>(ntReadVirtualMemoryx64 + 0x1F) = (DWORD64)&controlStructInTargetProcess->lpBaseAddress;
    *reinterpret_cast<DWORD*>(ntReadVirtualMemoryx64 + 0x2C) = (DWORD)&controlStructInTargetProcess->lpBuffer;
    *reinterpret_cast<SIZE_T*>(ntReadVirtualMemoryx64 + 0x39) = (SIZE_T)&controlStructInTargetProcess->nSize;

    *reinterpret_cast<DWORD*>(ntReadVirtualMemoryx64 + 0x53) = this->sharedMemoryInLauncherAddress;


    CopyMemory((void*)shellcodeBufferEndAddr, ntReadVirtualMemoryx64, sizeof(ntReadVirtualMemoryx64));
    shellcodeBufferEndAddr += sizeof(ntReadVirtualMemoryx64); 


    BYTE resetControllerAndJumpBack[] = {
      0xB8, 0,0,0,0,                               // +0x00       | mov eax,replace_with_operation_ptr
      0xC7, 0x00, 0,0,0,0,                         // +0x05       | MOV     DWORD PTR DS:[EAX],0x0
      0xE9, 0x63, 0xFF, 0xFF, 0xFF                 // +0xB        | JMP     spinlock start (unsigned int 4bytes) (TODO <- calculate this arbitrary number)
    };

    *reinterpret_cast<DWORD*>(resetControllerAndJumpBack + 0x01) = (DWORD)&controlStructInTargetProcess->operation;

    CopyMemory((void*)shellcodeBufferEndAddr, resetControllerAndJumpBack, sizeof(resetControllerAndJumpBack));
    shellcodeBufferEndAddr += sizeof(resetControllerAndJumpBack); 

    DWORD shellcodeSize = (((unsigned int)shellcodeBufferEndAddr) - ((unsigned int)shellcodeBuffer));
    if (!WriteProcessMemory(this->launcherHandle, (LPVOID)this->exploitableSectionInfo.nullBytesStartAddress, shellcodeBuffer, shellcodeSize, nullptr))
    {
        ResumeThread(this->launcherHijackingThreadHandler);
        notifyErrorAndExit("WriteProcessMemory failed 4!");
    }

    ExecWithThreadHiJacking(this->launcherHijackingThreadHandler, this->exploitableSectionInfo.nullBytesStartAddress, NULL , false);

};

// for getting an address of a procedure in memory.
PVOID GetLibraryProcAddress(const char LibraryName[], const char ProcName[])
{
  return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

// took it from the internet, the place where all good things come from.
// https://github.com/Zer0Mem0ry/WindowsNT-Handle-Scanner/blob/master/FindHandles/main.cpp
void GameLauncherController::getExistingHandlerToTheGame() {
    _NtQuerySystemInformation NtQuerySystemInformation =
      (_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject =
      (_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
    _NtQueryObject NtQueryObject =
      (_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    ULONG i;

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

    while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
      handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

    for (i = 0; i < handleInfo->HandleCount; i++)
    {
      SYSTEM_HANDLE handle = handleInfo->Handles[i];
      HANDLE dupHandle = NULL;
      POBJECT_TYPE_INFORMATION objectTypeInfo;
      PVOID objectNameInfo;
      UNICODE_ANOTHER_STRING objectName;
      ULONG returnLength;

      if (handle.ProcessId != this->launcherPid)
        continue;

      NT_SUCCESS(NtDuplicateObject(this->launcherHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0));

      objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
      NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL));

      if (handle.GrantedAccess == 0x0012019f)
      {
        std::free(objectTypeInfo);
        CloseHandle(dupHandle);
        continue;
      }

      objectNameInfo = malloc(0x1000);
      if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
      {
        objectNameInfo = realloc(objectNameInfo, returnLength);
        if (!NT_SUCCESS(NtQueryObject(
          dupHandle,
          ObjectNameInformation,
          objectNameInfo,
          returnLength,
          NULL
        )))
        {
          std::free(objectTypeInfo);
          std::free(objectNameInfo);
          CloseHandle(dupHandle);
          continue;
        }
      }
      // reinterpret_cast<DWORD*>(OpenFileMappingWShellcode + 0x0D) = addrOpenFileMappingWPtr;
      // objectName = reinterpret_cast<UNICODE_ANOTHER_STRING>(*(PUNICODE_ANOTHER_STRING)objectNameInfo);
      std::wstring ObjectBuffer = objectTypeInfo->Name.Buffer;

      // We are only interested about handles to processes
      if (ObjectBuffer.find(L"Process") != std::wstring::npos)
      {

        HANDLE CurrentProcess = GetCurrentProcess();
        // HANDLE procHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, handle.ProcessId);

        HANDLE DuplicatedHandle = 0;

        // Duplicating the handle, now we can do basically anything with it.
        if (DuplicateHandle(this->launcherHandle, (HANDLE)handle.Handle, CurrentProcess, &DuplicatedHandle, 0, false, DUPLICATE_SAME_ACCESS))
        {

          PVOID buffer2 = NULL;
          ULONG buffersize2 = 0;

          NTSTATUS status = NtQueryObject(this->launcherHandle, ObjectTypeInformation, buffer2, buffersize2, &buffersize2); // Return objecttypeinfo into buffer

          wchar_t process[MAX_PATH];
          if (GetModuleFileNameExW(DuplicatedHandle, NULL, process, MAX_PATH)) {
            std::wstring processname = process;
            int pos = processname.find_last_of(L"\\");
            processname = processname.substr(pos + 1, processname.length());
            if (processname == this->gameProcessName.c_str())
             {
              std::free(objectTypeInfo);
              std::free(objectNameInfo);
              CloseHandle(dupHandle);
              CloseHandle(DuplicatedHandle);
              //CloseHandle((HANDLE)handle.Handle);
              this->existingHandlerToTheGame = (HANDLE)handle.Handle;
              return;
            }
          }
        CloseHandle(DuplicatedHandle);
        }
      }
      std::free(objectTypeInfo);
      std::free(objectNameInfo);
      CloseHandle(dupHandle);
      //CloseHandle((HANDLE)handle.Handle);

    }

}


void GameLauncherController::cleanItUp() {
  CloseHandle(this->launcherHandle);
  CloseHandle(this->launcherHijackingThreadHandler);
}


uintptr_t* GameLauncherController::readGameMemory(DWORD64 readAddress, unsigned int lengthToRead) {
  if (lengthToRead > sharedMemoBufferWritableSize) {
    std::cout << "You are trying to read more than " << sharedMemoBufferWritableSize << " bytes. That's a no-no." << std::endl; 
    return nullptr;
  }

  SpinLockControlStruct* controlStructLocal = reinterpret_cast<SpinLockControlStruct*>(this->sharedMemoryLocalAddress);

  uintptr_t* localWriteBufferAddress = (uintptr_t*)(((BYTE*)(this->sharedMemoryLocalAddress))+ sharedMemoBufferOffset);
  uintptr_t* remoteWriteBufferAddress = (uintptr_t*)(this->sharedMemoryInLauncherAddress + sharedMemoBufferOffset);

  controlStructLocal->hProcess = (HANDLE)this->existingHandlerToTheGame;
  controlStructLocal->lpBaseAddress = readAddress;
  controlStructLocal->lpBuffer = (DWORD64)remoteWriteBufferAddress ;
  controlStructLocal->nSize = lengthToRead;
  controlStructLocal->operation = 1;
  while (controlStructLocal->operation != 0) {
    std::cout << "Reading! \n"; 
  }

  return localWriteBufferAddress;
}

void GameLauncherController::writeGameMemory(DWORD64 writeAddress, void* data, unsigned int lengthToWrite) {

  if (lengthToWrite > sharedMemoBufferWritableSize) {
    std::cout << "You are trying to write more than " << sharedMemoBufferWritableSize << " bytes. That's a no-no." << std::endl; 
    return;
  }

  SpinLockControlStruct* controlStructLocal = reinterpret_cast<SpinLockControlStruct*>(this->sharedMemoryLocalAddress);

  uintptr_t* localWriteBufferAddress = (uintptr_t*)(((BYTE*)(this->sharedMemoryLocalAddress))+ 0x50);
  uintptr_t* remoteWriteBufferAddress = (uintptr_t*)(this->sharedMemoryInLauncherAddress + 0x50);
  
  CopyMemory(localWriteBufferAddress, data, lengthToWrite);
  controlStructLocal->hProcess = (HANDLE)this->existingHandlerToTheGame;
  controlStructLocal->lpBaseAddress = writeAddress;
  controlStructLocal->lpBuffer = (DWORD64)remoteWriteBufferAddress ;
  controlStructLocal->nSize = lengthToWrite;
  controlStructLocal->operation = 2;
  while (controlStructLocal->operation != 0) {
    std::cout << "Writing! \n"; 
  }

}
