#pragma once

#include <windows.h>
#include <string>
#include "Utils.h"
#include <iostream>


namespace x86AddressesGrabber
{

    struct X86FunctionsAddress
    {
        DWORD addrOpenFileMappingWPtr = NULL;
        DWORD addrMapViewOfFilePtr = NULL;
        DWORD addrCloseHandlePtr = NULL;
        DWORD addrOpenProcess = NULL;
        DWORD addrOpenProcessJmpTo = NULL;
    };

    bool getFunctionAddresses(X86FunctionsAddress * x86FunctionsAddress);
    
    const std::wstring lpNameFilemappingx86Spy = L"x86Spy";
    const std::wstring spyProcessName = L"x86spy.exe";
    const DWORD sharedMemSize = 4096;
};

