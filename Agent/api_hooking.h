/*****************************************************************************
 * @file        api_hooking.cpp
 * @brief       api_hooking header
 * @author      Zied Sayari
 *
 *****************************************************************************/

#pragma once
#include "pch.h"
#include <winternl.h>



LPVOID allocate_mem_around_function(LPVOID);
void setup_hook(LPVOID target_func_to_hook, LPVOID payload_func, UINT32 stolen_bytes_size, LPVOID* ptr_ptr_original_func);
BOOL write_jmp_rax(LPVOID ptr_where_to_write_jump, LPVOID address_to_jump_to);
LPVOID get_win_api_func_addr(LPCSTR lib_name, LPCSTR function_name);
UINT32 setup_trampoline(LPVOID mem_regoin, LPVOID hooked_function, UINT32 stolen_bytes_size);

// Hooked functions
NTSTATUS NTAPI hooked_LdrLoadDll(PCWSTR, PULONG, PCUNICODE_STRING, PHANDLE);
int WINAPI hooked_MessageBoxA(HWND, LPCSTR, LPCSTR, UINT);

typedef NTSTATUS(NTAPI* func_ptr_LdrLoadDll)(PCWSTR, PULONG, PCUNICODE_STRING, PHANDLE);
typedef int (WINAPI* func_ptr_MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);

// trampoline pointers to continue execution
extern "C" func_ptr_LdrLoadDll ptr_original_LdrLoadDll;
extern "C" func_ptr_MessageBoxA ptr_original_MessageBoxA;



