#include "pch.h"
#include "communication.h"
#include "api_hooking.h"




DWORD WINAPI agent_main() {

    LPVOID NtOpenProcess_address = get_win_api_func_addr("ntdll.dll", "NtOpenProcess");
    if (!NtOpenProcess_address) {
        LogToEDR("Failed to get NtOpenProcess_address");
        return -1;
    }

    LPVOID NtAllocateVirtualMemory_address = get_win_api_func_addr("ntdll.dll", "NtAllocateVirtualMemory");
    if (!NtOpenProcess_address) {
        LogToEDR("Failed to get NtAllocateVirtualMemory");
        return -1;
    }

    LPVOID NtAllocateVirtualMemoryEx_address = get_win_api_func_addr("ntdll.dll", "NtAllocateVirtualMemoryEx");
    if (!NtOpenProcess_address) {
        LogToEDR("Failed to get NtAllocateVirtualMemoryEx");
        return -1;
    }

    LPVOID NtWriteVirtualMemory_address = get_win_api_func_addr("ntdll.dll", "NtWriteVirtualMemory");
    if (!NtOpenProcess_address) {
        LogToEDR("Failed to get NtWriteVirtualMemory");
        return -1;
    }

    LPVOID NtProtectVirtualMemory_address = get_win_api_func_addr("ntdll.dll", "NtProtectVirtualMemory");
    if (!NtOpenProcess_address) {
        LogToEDR("Failed to get NtProtectVirtualMemory");
        return -1;
    }

    LPVOID NtCreateThreadEx_address = get_win_api_func_addr("ntdll.dll", "NtCreateThreadEx");
    if (!NtCreateThreadEx_address) {
        LogToEDR("Failed to get NtCreateThreadEx");
        return -1;
    }

    LPVOID LdrLoadDll_address = get_win_api_func_addr("ntdll.dll", "LdrLoadDll");
    if (!LdrLoadDll_address) {
        LogToEDR("Failed to get LdrLoadDll_address");
        return -1;
    }
    
    setup_hook(NtOpenProcess_address, hooked_NtOpenProcess, 8, (LPVOID*)&ptr_original_NtOpenProcess);

    setup_hook(NtAllocateVirtualMemory_address, hooked_NtAllocateVirtualMemory, 8, (LPVOID*)&ptr_original_NtAllocateVirtualMemory);
    setup_hook(NtAllocateVirtualMemoryEx_address, hooked_NtAllocateVirtualMemoryEx, 8, (LPVOID*)&ptr_original_NtAllocateVirtualMemoryEx);
    
    setup_hook(NtWriteVirtualMemory_address, hooked_NtWriteVirtualMemory, 8, (LPVOID*)&ptr_original_NtWriteVirtualMemory);
    setup_hook(NtProtectVirtualMemory_address, hooked_NtProtectVirtualMemory, 8, (LPVOID*)&ptr_original_NtProtectVirtualMemory);
    setup_hook(NtCreateThreadEx_address, hooked_NtCreateThreadEx, 8, (LPVOID*)&ptr_original_NtCreateThreadEx);

    // MessageBoxA is hooked inside LdrLoadDll when user32.dll is loaded
    setup_hook(LdrLoadDll_address, hooked_LdrLoadDll, 7, (LPVOID *)&ptr_original_LdrLoadDll);
    LogToEDR("[+] agent_main finished.\n");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        agent_main();
    }
    return TRUE;
}
