#pragma once

#include "x86AddressesGrabber.h"
#include "utils.h"

struct SpinLockControlStruct {
    DWORD64 operation = 0; //0=do nothing, 1=read, 2=write
    HANDLE hProcess = NULL;
    DWORD64 lpBaseAddress = NULL;
    DWORD64 lpBuffer = 0;
    SIZE_T nSize = 0;
};

struct ExploitableSectionInfo
{

  uintptr_t startOfSectionAddr;
  uintptr_t endOfSectionAddr;
  uintptr_t nullBytesStartAddress;
  uintptr_t sectionEndAddress;
  int numberOfNullBytes;
};

class GameLauncherController
{
  public:

    GameLauncherController(std::wstring launcherName, std::wstring gameProcessName);
    std::wstring launcherName;
    std::wstring gameProcessName;
    

    void getLauncherInfo();
    void overwriteCreateProcessToGetFullAccess(uintptr_t addrOpenProcess, uintptr_t addrOpenProcessJmpTo);
    void setupSharedMemory(x86AddressesGrabber::X86FunctionsAddress* x86FunctionsAddressPtr);
    void deployControllerShellCode();
    void getExistingHandlerToTheGame();
    void cleanItUp();
    uintptr_t* readGameMemory(DWORD64 readAddress, unsigned int lengthToRead);
    void writeGameMemory(DWORD64 writeAddress, void* data, unsigned int lengthToRead);

  protected:
    HANDLE existingHandlerToTheGame;
    void getLauncherHandler();
    void setModuleBaseAddress();
    void findTheCodeCaveOnSectionNullBytes();
    HANDLE launcherHandle;
    uintptr_t launcherMainModuleBaseAddress;
    uintptr_t launcherPid;    
    HANDLE launcherHijackingThreadHandler;

    ExploitableSectionInfo exploitableSectionInfo;
    DWORD64* sharedMemoryLocalAddress;
    DWORD sharedMemoryInLauncherAddress;
    static const int sharedMemoBufferSize = 4096;
    // the first 0x40 is reserved for the spinlock control structure.
    static const int sharedMemoBufferOffset = 0x30;
    static const int sharedMemoBufferWritableSize = sharedMemoBufferSize - sharedMemoBufferOffset;
};
