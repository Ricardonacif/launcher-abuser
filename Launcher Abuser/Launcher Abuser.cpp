// Launcher Abuser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include "x86AddressesGrabber.h"
#include "GameLauncherController.h"

int main()
{
    std::cout << "Welcome to Launcher Abuser! Let's borrow some handlers :D\n";
    x86AddressesGrabber::X86FunctionsAddress x86FunctionsAddress = {};
    x86AddressesGrabber::getFunctionAddresses(&x86FunctionsAddress);

    std::wstring launcherName = L"steam.exe";
    std::wstring gameProcessName = L"cactus.exe";

    GameLauncherController gameLauncherCtl = {launcherName, gameProcessName};

    std::wcout << gameLauncherCtl.launcherName.c_str();
    gameLauncherCtl.getLauncherInfo();

    if (gameLauncherCtl.launcherName == L"steam.exe")
    {
        gameLauncherCtl.overwriteCreateProcessToGetFullAccess(x86FunctionsAddress.addrOpenProcess, x86FunctionsAddress.addrOpenProcessJmpTo);
    }

    unsigned int option = 0;
    std::cout << "Ok, now press enter when the game has loaded." << std::endl;
    std::cin >> option;


    gameLauncherCtl.setupSharedMemory(&x86FunctionsAddress);    
    gameLauncherCtl.deployControllerShellCode();    
    gameLauncherCtl.getExistingHandlerToTheGame();
    gameLauncherCtl.cleanItUp();


    while(true) {
        DWORD64 lpBaseAddress;
        unsigned int lengthToRead = 4;

        std::cout << "Address to write in OW: 0x";        
        std::cin >> std::hex >> lpBaseAddress;
        std::cout << "Length to read";
        std::cin >> std::hex >> lengthToRead;

        // gameLauncherCtl.writeGameMemory(lpBaseAddress, (void*)bufferToWritePtr,  4);

        uintptr_t *readDataPtr = gameLauncherCtl.readGameMemory(lpBaseAddress, lengthToRead);
        if (readDataPtr != nullptr)
        {
            printInHex((BYTE*)readDataPtr, lengthToRead);
        }



  }

}
