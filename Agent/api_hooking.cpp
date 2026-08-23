/*****************************************************************************
 * @file        api_hooking.cpp
 * @brief       api_hooking implementation
 * @author      Zied Sayari
 * 
 * @details
 *  API hooking logic
 *****************************************************************************/


#include "pch.h"
#include "api_hooking.h"
#include "communication.h"
#include <winternl.h>

//#define PRINT


func_ptr_LdrLoadDll ptr_original_LdrLoadDll = NULL;
func_ptr_MessageBoxA ptr_original_MessageBoxA = NULL;


// hooked_LdrLoadDll logs DllName and DllHandle then call original function and finally if user32.dll is loaded hook it
NTSTATUS NTAPI hooked_LdrLoadDll(PCWSTR DllPath, PULONG DllCharacteristics, PCUNICODE_STRING DllName, PHANDLE DllHandle) {
    char safeDllName[256] = {0};
    WstrToAnsi(DllName->Buffer, safeDllName, sizeof(safeDllName) - 1);

    LogToEDR("[HOOK HIT] LdrLoadDll called for: %s (HandlePtr: %p)", safeDllName, DllHandle);

    if (!ptr_original_LdrLoadDll) {
        LogToEDR("[AGENT LOG] Failed to get the return address to resume the original call to LdrLoadDll");
        return (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
    }

    NTSTATUS status = ptr_original_LdrLoadDll(DllPath, DllCharacteristics, DllName, DllHandle);
    
    if (NT_SUCCESS(status) && DllHandle && *DllHandle) {
        // hook message box when user32 is loaded imediately
        if (strcmp(safeDllName, "User32.dll") == 0) {
            HMODULE hMod = (HMODULE)*DllHandle;
            if (!hMod) {
                LogToEDR("Could not get a valid handle to user32.dll\n");
                return status;
            }
                

            FARPROC MessageBoxA_address = GetProcAddress(hMod, "MessageBoxA");
            setup_hook(MessageBoxA_address, hooked_MessageBoxA, 7, (LPVOID*)&ptr_original_MessageBoxA);
            LogToEDR("[+] MessageBoxA is hooked.\n");
        }
    }
    

    return status;
}


// hooked_MessageBoxA log parameters, modify them and finally call original function
int WINAPI hooked_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

    LogToEDR("[HOOK HIT] MessageBoxA is called \
        \n\tHWND : %p\
        \n\tlpText : %s\
        \n\tlpCaption : %s\
        \n\tuType: %lu\n"
        , hWnd, lpText, lpCaption, uType);



    if (!ptr_original_MessageBoxA) {
        LogToEDR("[AGENT LOG] Failed to get the return address to resume the original call to MessageBoxA");
        return IDOK;
    }
    LPCSTR custom_lpText = "EDR Hooked This!";
    LPCSTR custom_lpCaption = "Hello from EDR";
    UINT custom_uType = 1;
    return ptr_original_MessageBoxA(hWnd, custom_lpText, custom_lpCaption, custom_uType);
}

// allocate_mem_around_function find a free memory regoin near target_function then allocate it
LPVOID allocate_mem_around_function(LPVOID target_function) {
    SYSTEM_INFO sys_info = {0};
    GetSystemInfo(&sys_info);

    const uintptr_t page_size = sys_info.dwPageSize;
    uintptr_t start_address = uintptr_t(target_function) & ~(page_size - 1);

    uintptr_t min_address = min(start_address - 0x7FFFFF00, (uintptr_t)sys_info.lpMinimumApplicationAddress);
    uintptr_t max_address = max(start_address + 0x7FFFFF00, (uintptr_t)sys_info.lpMaximumApplicationAddress);

    uintptr_t start_page = start_address - (start_address % page_size);

    uintptr_t page_offset = 1;
    while (1) {

        uintptr_t byte_offset = page_offset * page_size;
        uintptr_t high_address = start_page + byte_offset;
        uintptr_t low_address = (start_page > byte_offset) ? start_page - byte_offset : 0;

        BOOL exit = (high_address > max_address) && (low_address < min_address);

        if (high_address < max_address) {
            LPVOID address = VirtualAlloc((LPVOID)high_address, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (address)
                return address;
        }

        if (low_address > min_address) {
            LPVOID address = VirtualAlloc((LPVOID)low_address, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (address)
                return address;
        }

        page_offset++;

        if (exit)
            break;

    }
    return nullptr;
}
// write an absolute jump to provided address inside the dest address, using RAX register
BOOL write_jmp_rax(LPVOID ptr_where_to_write_jump, LPVOID address_to_jump_to) {

    //BYTE jmp_rax_instructions[] = { 0x49, 0xBE, 0x00, 0x00 , 0x00 , 0x00, 0x00 , 0x00 , 0x00 , 0x00 // movabs r14, 0x00
    //, 0x41, 0xFF, 0xE6};                                                                    // jmp    r14

    BYTE jmp_rax_instructions[] = { 0x48, 0xB8, 0x00, 0x00 , 0x00 , 0x00, 0x00 , 0x00 , 0x00 , 0x00 // movabs r14, 0x00
        , 0xFF, 0xE0};   
    memcpy_s(jmp_rax_instructions + 2, sizeof(LPVOID), &address_to_jump_to, sizeof(LPVOID));
    DWORD old_protect = 0;
    if (!VirtualProtect(ptr_where_to_write_jump, sizeof(jmp_rax_instructions), PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    memcpy_s(ptr_where_to_write_jump, sizeof(jmp_rax_instructions), jmp_rax_instructions, sizeof(jmp_rax_instructions));
    
    DWORD temp_protect = 0;
    if (!VirtualProtect(ptr_where_to_write_jump, sizeof(jmp_rax_instructions), old_protect, &temp_protect)) {
        return false;
    }

    return true;
}
// Lookup function address from a DLL
LPVOID get_win_api_func_addr(LPCSTR lib_name, LPCSTR function_name) {
    FARPROC function_address = nullptr;

    HMODULE hMod = GetModuleHandleA(lib_name);
    if (!hMod) {

        hMod = LoadLibraryA(lib_name);
        return function_address;
    }

    function_address = GetProcAddress(hMod, function_name);


    return function_address;
}
// populate the trampoline with stolen bytes and write an absolute jump to the orginal function after the relative address
UINT32 setup_trampoline(LPVOID mem_regoin, LPVOID hooked_function, UINT32 stolen_bytes_size) {
    
    if (stolen_bytes_size < 5)
        return 0;


    LPVOID stolen_bytes_regoin = mem_regoin;
    LPVOID trampoline_jmp_back_regoin = (LPVOID)((BYTE*)mem_regoin + stolen_bytes_size);
    LPVOID absolute_table_regoin = (LPVOID)((BYTE*)trampoline_jmp_back_regoin + 12); // 12 is the size of x64 absolute jump

    // copy stolen bytes to 
    memcpy_s(stolen_bytes_regoin, stolen_bytes_size, hooked_function, stolen_bytes_size);


    LPVOID address_where_continue_from_hooked_func = (LPVOID)((BYTE*)hooked_function + stolen_bytes_size);
    write_jmp_rax(trampoline_jmp_back_regoin, address_where_continue_from_hooked_func);

    
    UINT32 trampoline_size = (UINT32)((uintptr_t)absolute_table_regoin - (uintptr_t)mem_regoin) ;

    return trampoline_size;
}
// call setup_trampoline
// setup relay_address to call hook pyaload
// patch original function with relative jump
// assign ptr_original_func with trampoline address
void setup_hook(LPVOID target_func_to_hook, LPVOID payload_func,  UINT32 stolen_bytes_size, LPVOID * ptr_ptr_original_func) {

    if (stolen_bytes_size < 5)
        return;

    DWORD old_protect = 0;
    if (!VirtualProtect(target_func_to_hook, stolen_bytes_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return;
    }
    
    LPVOID hook_memory_regoin = allocate_mem_around_function(target_func_to_hook);
    memset(hook_memory_regoin, 0x90, 1024);

    if (!hook_memory_regoin)
        return;
    //
    LPVOID trampoline_address = hook_memory_regoin;
    INT32 trampoline_size = setup_trampoline(trampoline_address, target_func_to_hook, stolen_bytes_size);
    
    LPVOID relay_address = (LPVOID)((BYTE*)trampoline_address + trampoline_size);
    if (!write_jmp_rax(relay_address, payload_func))
        return;

    BYTE relative_jmp_instructions[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    INT32 relative_address_from_relay_to_hooked_func = INT32((INT64)relay_address
                                                     - (INT64)((BYTE*)target_func_to_hook + sizeof(relative_jmp_instructions)));


    memset(target_func_to_hook, 0x90, stolen_bytes_size);
    memcpy_s(relative_jmp_instructions + 1, sizeof(UINT32), &relative_address_from_relay_to_hooked_func, sizeof(UINT32));
    memcpy_s(target_func_to_hook, sizeof(relative_jmp_instructions), relative_jmp_instructions, sizeof(relative_jmp_instructions));

#ifdef PRINT
    printf("target function address : %p\nhook memory address : %p\n", target_func_to_hook, hook_memory_regoin);
    printf("jmp insturc : %02x, %02x, %02x, %02x, %02x\n", relative_jmp_instructions[0], relative_jmp_instructions[1], relative_jmp_instructions[2], relative_jmp_instructions[3], relative_jmp_instructions[4]);
    printf("jmp relative address : %04x\n", relative_address_from_relay_to_hooked_func);
#endif // PRINT
    
    DWORD temp_protect = 0;
    if (!VirtualProtect(target_func_to_hook, stolen_bytes_size, old_protect, &temp_protect)) {
        return;
    }
    FlushInstructionCache(GetCurrentProcess(), target_func_to_hook, stolen_bytes_size);
    *ptr_ptr_original_func = (LPVOID)trampoline_address;

    return;
}