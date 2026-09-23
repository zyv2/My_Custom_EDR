/*****************************************************************************
 * @file        api_hooking.cpp
 * @brief       api_hooking header
 * @author      Zied Sayari
 *
 *****************************************************************************/

#pragma once
#include "custom_types.h"
#include "pch.h"




LPVOID allocate_mem_around_function(LPVOID);
void setup_hook(LPVOID target_func_to_hook, LPVOID payload_func, UINT32 stolen_bytes_size, LPVOID* ptr_ptr_original_func);
BOOL write_jmp_rax(LPVOID ptr_where_to_write_jump, LPVOID address_to_jump_to);
BOOL write_jmp_r11(LPVOID ptr_where_to_write_jump, LPVOID address_to_jump_to);
LPVOID get_win_api_func_addr(LPCSTR lib_name, LPCSTR function_name);
UINT32 setup_trampoline(LPVOID mem_regoin, LPVOID hooked_function, UINT32 stolen_bytes_size);

// Hooked functions
NTSTATUS NTAPI hooked_LdrLoadDll(PCWSTR, PULONG, PCUNICODE_STRING, PHANDLE);
int WINAPI hooked_MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);
NTSTATUS NTAPI hooked_NtCreateThreadEx(PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PUSER_THREAD_START_ROUTINE StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);
NTSTATUS NTAPI hooked_NtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

NTSTATUS NTAPI hooked_NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);


NTSTATUS NTAPI hooked_NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
);
NTSTATUS NTAPI hooked_NtWriteVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);
NTSTATUS NTAPI hooked_NtProtectVirtualMemory (
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
);

typedef NTSTATUS(NTAPI* func_ptr_LdrLoadDll)(PCWSTR, PULONG, PCUNICODE_STRING, PHANDLE);
typedef int (WINAPI* func_ptr_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef NTSTATUS(NTAPI* func_ptr_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, 
    PUSER_THREAD_START_ROUTINE,
    PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
/*-----------------------------------------NtOpenProcess-----------------------------------------*/

typedef NTSTATUS(NTAPI* func_ptr_NtOpenProcess)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
);

/*-------------------------------------------NtAllocateVirtualMemory/Ex--------------------------*/

typedef NTSTATUS(NTAPI* func_ptr_NtAllocateVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);

typedef NTSTATUS(NTAPI* func_ptr_NtAllocateVirtualMemoryEx)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
);


/*-------------------------------------------NtWriteVirtualMemory--------------------------------*/

typedef NTSTATUS(NTAPI* func_ptr_NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

/*-------------------------------------------NtProtectVirtualMemory------------------------------*/

typedef NTSTATUS(NTAPI* func_ptr_NtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtection,
    _Out_ PULONG OldProtection
);


// trampoline pointers to continue execution
EXTERN_C func_ptr_LdrLoadDll ptr_original_LdrLoadDll;
EXTERN_C func_ptr_MessageBoxA ptr_original_MessageBoxA;
EXTERN_C func_ptr_NtCreateThreadEx ptr_original_NtCreateThreadEx;
EXTERN_C func_ptr_NtOpenProcess ptr_original_NtOpenProcess;
EXTERN_C func_ptr_NtAllocateVirtualMemoryEx ptr_original_NtAllocateVirtualMemoryEx;
EXTERN_C func_ptr_NtAllocateVirtualMemory ptr_original_NtAllocateVirtualMemory;
EXTERN_C func_ptr_NtWriteVirtualMemory ptr_original_NtWriteVirtualMemory;
EXTERN_C func_ptr_NtProtectVirtualMemory ptr_original_NtProtectVirtualMemory;



