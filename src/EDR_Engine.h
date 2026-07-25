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
	std::unordered_set<std::string> maliciouse_hashes = {"a3d2cc15de11fc08beb54a08827fee2f63fd8cec9c58273a912e37fb111c9d", "e7e19e9dbb93dd266b04fe62c1ee52bb86a423588305292ce7e929d0479df489", "45e8530e4005bb8fb19e176f7e3f979b6f1fe9c6827679d92bf522abf7613699"};

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

	
	// Remediation
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

