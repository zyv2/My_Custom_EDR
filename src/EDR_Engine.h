/*****************************************************************************
 * @file        EDR_Engine.cpp
 * @brief       My_Custom_EDR class header
 * @author      Zied Sayari
 *
 *
 * @details
 * Evolving user-mode Endpoint Detection and Response prototype. Implements
 * low-level Windows Debugging APIs to intercept injected modules, safely
 * parse Portable Executable (PE) headers, and execute surgical inline memory
 * patching (ret) to force safe initialization failure.
 *****************************************************************************/


#pragma once
#include <Windows.h>
#include <psapi.h>
#include <bcrypt.h>

#include <iostream>
#include <vector>
#include <unordered_set>

#pragma comment(lib, "bcrypt.lib")


class EDR_Engine
{
private:

	// Class internal members
	void* si = NULL;
	PROCESS_INFORMATION pi = {0};
	BOOL process_creation_status = 0;
	
	// threats database
	// unordered_set for constant lookup time

	// Test hash for evil.dll
	std::unordered_set<std::string> maliciouse_hashes = {"45e8530e4005bb8fb19e176f7e3f979b6f1fe9c6827679d92bf522abf7613699"};

	const char* critical_dlls[3] = { "ntdll.dll", "kernel32.dll", "lsass.exe" };

	// Class internal functions
	void handle_to_filename(HANDLE, char **);
	void translate_path(char*);


	/*
		Detection Function - evaluate_module()

		- Stages of The Function:
			Stage 1: Skip Trusted Directories that require administrator privs
			Stage 2: Look for critical dll names that is not in their default path
			Stage 3: Signature-based Detection


		- Internal Functions Used:
			is_trusted_dir()
			is_spoofed_threat
			hash_file
		
		- Return Value:
			True  : if the module is maliciouse
			False : if the module is safe 

	*/
	BOOL evaluate_module(HANDLE, char*);
	BOOL is_trusted_dir(char*);
	BOOL is_spoofed_threat(char*);
	
	// uses sha256
	std::string hash_file(HANDLE);

	
	/*
		REMEDIATION Function - evaluate_module()

		- Stages of The Function:
			Stage 1: Climb the PE structre to get the entry point offset
			Stage 2: Add offset to base address of the DLL; Get Entry-point Address
			Stage 3: SModify the first byte to be 0xc3 (ret)


		- Internal Functions Used:
			None

		- Return Value:
			None

	*/
	void modify_entry_point(HANDLE, LPVOID, DWORD);
	
	

public:
	// avoid this for now
	// not fully implemented
	EDR_Engine(LPCWSTR);
	
	// Ready
	EDR_Engine(LPCSTR);

	// Telemetry
	void monitor();

	// INFO functions
	void show_process_info();


	~EDR_Engine();
};

