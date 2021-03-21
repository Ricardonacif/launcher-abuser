# Launcher Abuser

Stealthy way to hijack the existing game process handle within the game launcher (currently supports Steam and Battle.net). Achieve external game process read/write with minimum footprint. 
<p align="center">
  <img src="/demo.gif?raw=true" width="200px">
</p>

## Core Concepts:
- **No new handles**: The LA (Launcher Abuser/cheat) process communicates with the game launcher using [Named Shared Memory](https://docs.microsoft.com/en-us/windows/win32/memory/using-file-mapping?redirectedfrom=MSDN), but the LA->game launcher handle is destroyed before the game is loaded (and the communication still works without it).
- **No new modules**: A 154 bytes shellcode is injected into the game launcher to handle read and write requests using a spinlock and the shared memory.
- **No new threads**: An existing game launcher thread is hijacked so there's less footprint.
- **No new executable memory pages**: Since it's a 154 bytes shellcode, an existing executable page memory is used as a codecave for the spinlock (and the following read/write operations).

## How It Works
It abuses the existing game process handle that the launchers keep (usually with full permissions). The LA process controls the game launcher process using it to send read and write commands to the game process. The thing that allows us to have an inter-process communication without a handle between the LA process and the game launcher is the fact that you can destroy the handle after setting up the named shared memory (before the game gets loaded). A thread is hijacked from the game launcher process, and the execution redirected to an an eternal loop shellcode. This shellcode keeps checking if the operation byte is set. When the LA process wants to read or write to the game process, it writes the shared memory on his own process the arguments for NtReadVirtualMemory/NtWriteVirtualMemory and sets the operation byte. That memory is reflected on the game launcher process, and the spinlock gets to execute the operation and stores the result on an offset of the same shared memory. 

## How It Actually Works
Considering game launchers that are x86, here's what it does step by step:
1. Spawns a x86 process to get the addresses of the functions [OpenFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-openfilemappingw), [MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) and [CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle). Those addresses are the same across all Windows processes, so they are used in the shellcode.
2. Searches for a codecave in the game launcher, and injects a shellcode that will establish the IPC using the named shared memory and close the handle right after.
3. Hijacks the game launcher main thread and makes it execute the IPC setup shellcode. The LA process waits for the first bytes of the shared memory to be updated with the address of the shared memory in the game launcher process.
4. The spinlock shellcode is deployed in the shared memory and the game launcher's thread is redirected to it.
5. From now on, the LA process has control of the operations thru the shared memory. If the control byte is 0, it will keep looping. If it's 1, it'll perform a read operation and 2 a write operation. It uses a few instructions to transict to x64 mode so we don't have to worry about [WoW64's Heaven's Gate](https://medium.com/@fsx30/hooking-heavens-gate-a-wow64-hooking-technique-5235e1aeed73) and we can simply use syscall opcodes to perform `NtReadVirtualMemory/NtWriteVirtualMemory`. The parameters for the functions are passed in the following struct:
 
```cpp
        struct SpinLockControlStruct {
            DWORD64 operation = 0; //0=do nothing, 1=read, 2=write
            HANDLE hProcess = NULL;
            DWORD64 lpBaseAddress = NULL;
            DWORD64 lpBuffer = 0;
            SIZE_T nSize = 0;
        };
 ```
6. After the operation, the result (if it's a read) comes in a specific offset of the shared memory.

## How to Use It
The example on `Launcher Abuser.cpp`'s main function is pretty self explanatory. Just call the functions below after the setup and do whatever you want:
```cpp
//this function reads from the game memory
uintptr_t *dataPtr = gameLauncherCtl.readGameMemory(lpBaseAddress, lengthToRead);

//this function writes on the game memory
gameLauncherCtl.writeGameMemory(lpBaseAddress, (void*)bufferToWritePtr,  size);

```
## Disclaimer
The project was developed for education purposes only. Nothing here is new and it was somewhat based on (this great project by harakirinox)[https://www.unknowncheats.me/forum/anti-cheat-bypass/261176-silentjack-ultimate-handle-hijacking-user-mode-multi-ac-bypass-eac-tested.html]. It should not be used to cheat in online games. It ain't cool kids. Also, as always, big shout-out to [Guided Hacking](https://guidedhacking.com). Best game hacking learning resources on the internet. You should check them out if you haven't yet.