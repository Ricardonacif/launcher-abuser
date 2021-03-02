// x86spy.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>

#include <windows.h>

#include <tchar.h>

#include <stdio.h>

#include <string>

int main()
{
    std::cout << "<--- x86Spy.exe ---> Getting function addresses.\n";
    
    DWORD addrOpenFileMappingW = (DWORD)GetProcAddress(GetModuleHandle(TEXT("kernelbase.dll")), "OpenFileMappingW");
    DWORD addrMapViewOfFile = (DWORD)GetProcAddress(GetModuleHandle(TEXT("kernelbase.dll")), "MapViewOfFile");
    DWORD addrCloseHandle = (DWORD)GetProcAddress(GetModuleHandle(TEXT("kernelbase.dll")), "CloseHandle");
    DWORD addrOpenProcess = (DWORD)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "OpenProcess");
    DWORD addrOpenProcessJmpTo = (DWORD)(*(DWORD*)(addrOpenProcess + 0x8));


    DWORD sharedMemSize = 4096;

    std::wstring sharedMemName = L"x86Spy";

    HANDLE hLocalSharedMem = NULL;

    while (hLocalSharedMem == NULL) {
        hLocalSharedMem = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, sharedMemName.c_str());
        Sleep(1000);
    }

    void* ptrLocalSharedMem = MapViewOfFile(hLocalSharedMem, FILE_MAP_ALL_ACCESS, 0, 0, sharedMemSize);
    if (!ptrLocalSharedMem) {
        return 0;
    }

    CloseHandle(hLocalSharedMem);
    while (true) {
        *(DWORD*)ptrLocalSharedMem = addrOpenFileMappingW;
        *((DWORD*)ptrLocalSharedMem + 1) = addrMapViewOfFile;
        *((DWORD*)ptrLocalSharedMem + 2) = addrCloseHandle;
        *((DWORD*)ptrLocalSharedMem + 3) = addrOpenProcess;
        *((DWORD*)ptrLocalSharedMem + 4) = addrOpenProcessJmpTo;

        std::cout << "<--- x86Spy.exe ---> I'm done, feel free to kill me.\n";

        Sleep(2000);
    }

}
