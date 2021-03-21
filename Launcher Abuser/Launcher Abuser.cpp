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

    unsigned int option = 0;
    while (option <1 || option > 3) {
        std::cout << "What game launcher do you want to borrow the handler from?" << std::endl;
        std::cout << "1- Steam" << std::endl;
        std::cout << "2- Battle.net" << std::endl;
        std::cout << "3- Other" << std::endl;
        std::cin >> option;
    }

    std::wstring launcherName;
    std::wstring gameProcessName;


    switch(option) {
    case 1:
      launcherName = L"steam.exe";
      break; 
    case 2:
      launcherName = L"Battle.net.exe";
      break;   
    case 3:
      std::wcin >> launcherName;
      break;
    }

    std::wcout << "Ok, " << launcherName << " will be." << std::endl;

    std::cout << "What is the game process name (don't launch it yet)?" << std::endl;
    std::wcin >> gameProcessName;

    GameLauncherController gameLauncherCtl = {launcherName, gameProcessName};

    std::wcout << gameLauncherCtl.launcherName.c_str();
    gameLauncherCtl.getLauncherInfo();

    if (gameLauncherCtl.launcherName == L"steam.exe")
    {
        gameLauncherCtl.overwriteCreateProcessToGetFullAccess(x86FunctionsAddress.addrOpenProcess, x86FunctionsAddress.addrOpenProcessJmpTo);
    }

    std::cout << "Ok, now press enter when the game has loaded." << std::endl;
    std::cin >> option;


    gameLauncherCtl.setupSharedMemory(&x86FunctionsAddress);    
    gameLauncherCtl.deployControllerShellCode();    
    gameLauncherCtl.getExistingHandlerToTheGame();
    gameLauncherCtl.cleanItUp();


    while(true) {
        DWORD64 lpBaseAddress;
        unsigned int lengthToRead = 4;

        std::cout << "Address to read in the game: 0x";        
        std::cin >> std::hex >> lpBaseAddress;
        std::cout << "\n Length to read in hex:";
        std::cin >> std::hex >> lengthToRead;
        std::cout << std::endl;

        // gameLauncherCtl.writeGameMemory(lpBaseAddress, (void*)bufferToWritePtr, 4);

        uintptr_t *readDataPtr = gameLauncherCtl.readGameMemory(lpBaseAddress, lengthToRead);
        if (readDataPtr != nullptr)
        {
            printInHex((BYTE*)readDataPtr, lengthToRead);
        }

  }

}
