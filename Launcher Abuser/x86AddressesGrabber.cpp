#include "x86AddressesGrabber.h"

bool x86AddressesGrabber::getFunctionAddresses(X86FunctionsAddress * x86FunctionsAddress) {

  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  ZeroMemory( &si, sizeof(si) );
  si.cb = sizeof(si);
  ZeroMemory( &pi, sizeof(pi) );
  
  const wchar_t* app_const = spyProcessName.c_str();


  if( !CreateProcessW( NULL,   // No module name (use command line)
      (LPWSTR)app_const,         // Command line
      NULL,           // Process handle not inheritable
      NULL,           // Thread handle not inheritable
      FALSE,          // Set handle inheritance to FALSE
      0,              // No creation flags
      NULL,           // Use parent's environment block
      NULL,           // Use parent's starting directory 
      &si,            // Pointer to STARTUPINFO structure
      &pi )           // Pointer to PROCESS_INFORMATION structure
  ) 
  {
      notifyErrorAndExit("Error creating the x86spy process!");
  }

  HANDLE hLocalSharedMem = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT | SEC_NOCACHE, 0, sharedMemSize, (LPCWSTR)lpNameFilemappingx86Spy.c_str() );
  if (!hLocalSharedMem)
    return false;
  VOID * ptrLocalSharedMem = MapViewOfFile(hLocalSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, sharedMemSize);
  if (!ptrLocalSharedMem)
    return false;
  
  while(*(DWORD*)ptrLocalSharedMem == 0x0) {
    std::cout << "Waiting for x86 spy process to update the addresses..." << std::endl;
    Sleep(2000);
  }

  x86FunctionsAddress->addrOpenFileMappingWPtr = *(DWORD*)ptrLocalSharedMem;
  x86FunctionsAddress->addrMapViewOfFilePtr = *((DWORD*)ptrLocalSharedMem+1);
  x86FunctionsAddress->addrCloseHandlePtr = *((DWORD*)ptrLocalSharedMem+2);
  x86FunctionsAddress->addrOpenProcess = *((DWORD*)ptrLocalSharedMem+3);
  x86FunctionsAddress->addrOpenProcessJmpTo = *((DWORD*)ptrLocalSharedMem+4);

  std::cout << "Addresses updated! Closing x86 spy process "<< std::hex << x86FunctionsAddress->addrOpenProcessJmpTo << std::endl;  

  TerminateProcess(
    pi.hProcess,
    0x0
  );
  CloseHandle( hLocalSharedMem );
  CloseHandle( pi.hProcess );
  CloseHandle( pi.hThread );

}