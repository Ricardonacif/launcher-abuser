#include "Utils.h"

std::string GetLastErrorAsString() {
  //Get the error message, if any.
  DWORD errorMessageID = ::GetLastError();
  if (errorMessageID == 0)
    return std::string(); //No error message has been recorded

  LPSTR messageBuffer = nullptr;
  size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) & messageBuffer, 0, NULL);

  std::string message(messageBuffer, size);

  //Free the buffer.
  LocalFree(messageBuffer);

  return message;
}

void notifyErrorAndExit(const char * text) {
  std::cout << "---!!! Error ---!!!" << std::endl;
  std::cout << "---!!! " << text <<" ---!!!" << std::endl;

  std::cout << GetLastErrorAsString() << std::endl;
  std::cout << "Process will exit after any key press. Fix your shit." << std::endl;
  std::cin.get();
  ExitProcess(1);
}

void LogThis(const char * text) {
  std::cout << "--==-- " << text << " --==--\n";
}

char * TO_CHAR(wchar_t * string) {
  size_t len = wcslen(string) + 1;
  char * c_string = new char[len];
  size_t numCharsRead;
  wcstombs_s( & numCharsRead, c_string, len, string, _TRUNCATE);
  return c_string;
}

PEB * GetPEB() {
  #ifdef _WIN64
  PEB * peb = (PEB * ) __readgsword(0x60);

  #else
  PEB * peb = (PEB * ) __readfsdword(0x30);
  #endif

  return peb;
}

LDR_DATA_TABLE_ENTRY * GetLDREntry(std::string name) {
  LDR_DATA_TABLE_ENTRY * ldr = nullptr;

  PEB * peb = GetPEB();

  LIST_ENTRY head = peb -> Ldr -> InMemoryOrderModuleList;

  LIST_ENTRY curr = head;

  while (curr.Flink != head.Blink) {
    LDR_DATA_TABLE_ENTRY * mod = (LDR_DATA_TABLE_ENTRY * ) CONTAINING_RECORD(curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    if (mod -> FullDllName.Buffer) {
      char * cName = TO_CHAR(mod -> BaseDllName.Buffer);

      if (_stricmp(cName, name.c_str()) == 0) {
        ldr = mod;
        break;
      }
      delete[] cName;
    }
    curr = * curr.Flink;
  }
  return ldr;
}

void ExecWithThreadHiJacking(HANDLE hThread, DWORD shellcodePtr, SIZE_T shellcodeSize, bool thenRestore) {
  WOW64_CONTEXT tcInitial;
  WOW64_CONTEXT tcHijack;
  WOW64_CONTEXT tcCurrent;
  SecureZeroMemory(&tcInitial, sizeof(WOW64_CONTEXT));
  tcInitial.ContextFlags = WOW64_CONTEXT_ALL;
 
  // Suspend the thread and make it execute our shellcode

  DWORD suspendCount = SuspendThread(hThread);
  if (suspendCount > 0) // The thread was already suspended
    for (int i(0); i < suspendCount; ++i)
      ResumeThread(hThread);
  Wow64GetThreadContext(hThread, &tcInitial);
  CopyMemory(&tcHijack, &tcInitial, sizeof(WOW64_CONTEXT));
  CopyMemory(&tcCurrent, &tcInitial, sizeof(WOW64_CONTEXT));
  
  tcHijack.Eip = (DWORD)shellcodePtr;

  Wow64SetThreadContext(hThread, &tcHijack);
  ResumeThread(hThread);
 
  if (shellcodeSize == NULL)
    return; // Permanent thread hijack, do not wait for any execution completion
 
  // Check the thread context to know when done executing (Eip should be at memory address + size of shellcode - 2 in the infinite loop jmp rel8 -2)
  DWORD addrEndOfExec = (DWORD)shellcodePtr + shellcodeSize - 2;
  do {
    Wow64GetThreadContext(hThread, &tcCurrent);
    Sleep(1000);
  } while (tcCurrent.Eip != addrEndOfExec);

  if (thenRestore) {
    // Execution finished, resuming previous operations
    SuspendThread(hThread);
    Wow64SetThreadContext(hThread, &tcInitial);
    ResumeThread(hThread);
  }
 
  return;
}


HANDLE getThreadHandleBasedOnStartAddress(HANDLE processHandle, uintptr_t startOfSectionAddr, uintptr_t endOfSectionAddr) 
{
  tNtQueryInformationThread NtQueryInformationThread = (tNtQueryInformationThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");

  THREADENTRY32 TE32{ 0 };
  TE32.dwSize = sizeof(TE32);
  
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(processHandle));
  if (hSnap == INVALID_HANDLE_VALUE)
  {
    notifyErrorAndExit("CreateToolhelp32Snapshot on hijackMainThread failed!");
  }

  DWORD dwTargetPID = GetProcessId(processHandle);
  DWORD ThreadID = 0;

  BOOL bRet = Thread32First(hSnap, &TE32);
  if (!bRet)
  {
    notifyErrorAndExit("Getting the handle failed!");
  }

  do
  {

    if (TE32.th32OwnerProcessID == dwTargetPID)
    {
      ThreadID = TE32.th32ThreadID;
      HANDLE hThread = OpenThread( THREAD_QUERY_INFORMATION |THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, TE32.th32ThreadID);
      if (!hThread)
      {
        notifyErrorAndExit("Getting the handle failed!");
      }

      unsigned  long  long dwStartAddress;
      NTSTATUS ntStatus = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(unsigned  long  long), NULL);
      if(ntStatus != 0x0) {
        notifyErrorAndExit("NtQueryInformationThread failed!");
      } 

      if (dwStartAddress >= startOfSectionAddr && dwStartAddress < endOfSectionAddr )
      {      
        CloseHandle(hSnap);
        return hThread;
      }
      CloseHandle(hThread);

      // break;
    }

    
    bRet = Thread32Next(hSnap, &TE32);
  } while (bRet);
  CloseHandle(hSnap);
  if (!ThreadID)
  {
    return NULL;
  }

}

void printInHex(BYTE* address, unsigned int length) {
    for (size_t i = 0; i < length; i++)
    {
        printf("%02hhx ", (unsigned char)(*(address + i)));
    }
    std::cout << "\n";

}
