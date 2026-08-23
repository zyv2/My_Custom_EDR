#include "pch.h"
#include "communication.h"
#include "api_hooking.h"




DWORD WINAPI agent_main() {
    LPVOID LdrLoadDll_address = get_win_api_func_addr("ntdll.dll", "LdrLoadDll");
    if (!LdrLoadDll_address) {
        LogToEDR("Failed to get LdrLoadDll_address");
        return -1;
    }
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
