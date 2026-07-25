
#include "EDR_Engine.h"


EDR_Engine::EDR_Engine(LPCWSTR program_path) {
	si = malloc(sizeof(STARTUPINFOW));
	


	if (si) {
		ZeroMemory(si, sizeof(STARTUPINFOW));
		
		// Used the Wide char because its faster
		// Windows is built on wide string
		// even when using the `A` version its converted and the `W` version is called under the hood
		process_creation_status = CreateProcessW(program_path, NULL, NULL, NULL, false, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, (LPSTARTUPINFOW)si, &pi);
	}
}

EDR_Engine::EDR_Engine(LPCSTR program_path) {


	si = malloc(sizeof(STARTUPINFOA));
	
	if (si) {
		ZeroMemory(si, sizeof(STARTUPINFOA));
		process_creation_status = CreateProcessA(program_path, NULL, NULL, NULL, false, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, (LPSTARTUPINFOA)si, &pi);
	}
}

void EDR_Engine::monitor()
{	
	DWORD dwState = DBG_CONTINUE;
	bool is_running = true;
	DEBUG_EVENT event = { 0 };
	HANDLE hProcess = 0;
	DWORD file_size = 0;


	char* temp_filename = (char*)malloc(MAX_PATH + 1);
	if (temp_filename) {
		ZeroMemory(temp_filename, MAX_PATH + 1);
	}


	while (is_running) {
		
		if (!WaitForDebugEvent(&event, INFINITE)) {
			return;
		}

		switch (event.dwDebugEventCode) {

		case CREATE_PROCESS_DEBUG_EVENT:
			hProcess = event.u.CreateProcessInfo.hProcess;
			printf("Process Created With Handle : %p\n", hProcess);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			handle_to_filename(event.u.LoadDll.hFile, &temp_filename);
			printf("DLL Has Been Loaded With Handle : %p\nDLL Path : %s\n", event.u.LoadDll.hFile, temp_filename);
			
			translate_path(temp_filename);
			printf("DOS Path : %s\n", temp_filename);

			puts("");

			if (evaluate_module(event.u.LoadDll.hFile, temp_filename)) {
				// remdiete
				puts("[!] Remediation Phase:");
				file_size = GetFileSize(event.u.LoadDll.hFile, 0);
				modify_entry_point(hProcess, event.u.LoadDll.lpBaseOfDll, file_size);
			}
			
			// check and cleanup 
			if (event.u.LoadDll.hFile != NULL && event.u.LoadDll.hFile != INVALID_HANDLE_VALUE) {
				CloseHandle(event.u.LoadDll.hFile);
			}
			break;
		default:
			dwState = DBG_CONTINUE;
		}

		ContinueDebugEvent(event.dwProcessId, event.dwThreadId, dwState);
		dwState = DBG_CONTINUE;
	}
}



void EDR_Engine::handle_to_filename(HANDLE hDll, char **filename) { 

	HANDLE hFileMap = CreateFileMappingW(hDll, nullptr, PAGE_READONLY, 0, 1, nullptr);
	char path[MAX_PATH + 1] = { 0 };
	if (hFileMap) {
		LPVOID mem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
		if (mem) {
			if (GetMappedFileNameA(GetCurrentProcess(), mem, path, MAX_PATH)) {
				strncpy_s(*filename, MAX_PATH, path, strlen(path)+1);
			}
			else
			{
				printf("GetMappedFileNameA failed %x\n", GetLastError());
			}
			UnmapViewOfFile(mem);
		}
		else
		{
			printf("MapViewOfFile failed\n");
		}
		CloseHandle(hFileMap);
	}
	else
	{
		printf("CreateFileMappingW failed\n");
	}
	return;
}


void EDR_Engine::translate_path(char* path)
{
	if (!path || path[0] == '\0') return;

	char driveLetter[3] = "A:";
	char deviceMapping[MAX_PATH] = { 0 };

	// Loop through all potential drives (A: to Z:)
	for (char c = 'A'; c <= 'Z'; ++c) {
		driveLetter[0] = c;

		if (QueryDosDeviceA(driveLetter, deviceMapping, MAX_PATH) != 0) {

			if (strncmp(path, deviceMapping, strlen(deviceMapping)) == 0) {

				char tempPath[MAX_PATH] = { 0 };

				// [drive letter] + [rest of path]
				strcpy_s(tempPath, MAX_PATH, driveLetter);
				strcat_s(tempPath, MAX_PATH, path + strlen(deviceMapping));

				// Overwrite the original buffer
				strcpy_s(path, MAX_PATH, tempPath);
				return;
			}
		}
	}
}

BOOL EDR_Engine::evaluate_module(HANDLE hFile, char* dos_path)
{
	// Stage 1:  Skip Trusted Directories that require administrator privs
	if (is_trusted_dir(dos_path)) {
		return false;
	}
	else
	{
		// Stage 2: Look for critical dll names that is not in their normal path
		if (is_spoofed_threat(dos_path)) {
			std::cout << "[ALERT] Path Spoofing Attack Detected:" << '\n' <<
				"	Module Path : " << dos_path << std::endl;
			return true;
		}
		else
		{
			std::string file_hash = hash_file(hFile);

			// Stage 3: Signature-based Detection 
			if (!file_hash.empty() && maliciouse_hashes.find(file_hash) != maliciouse_hashes.end()) {

				std::cout << "[ALERT] Known Signature Detected:" << '\n' <<
					"	Module Path : " << dos_path << '\n' <<
					"	Path : " << dos_path << '\n' <<
					"	Hash : " << file_hash << std::endl;
				return true;
			}

		}	
	}
	return false;
}

BOOL EDR_Engine::is_trusted_dir(char* path)
{	

	/*
		HARDCODED PATHS 
		for now,
		Will be refactored properly later
	*/
	const char* trusted_path = "C:\\Windows";

	const char* untrusted_path1 = "C:\\Windows\\Temp\\";
	const char* untrusted_path2 = "C:\\Windows\\Tasks\\";

	if (strncmp(path, trusted_path, strlen(trusted_path)) == 0) {

		if (strncmp(path, untrusted_path1, strlen(untrusted_path1)) == 0 || 
			strncmp(path, untrusted_path2, strlen(untrusted_path2)) == 0 ) 
		{
			return false;
		}

		return true;
	}
	return false;
}

BOOL EDR_Engine::is_spoofed_threat(char* path)
{
	for (auto dll : critical_dlls) {
		if (strstr(path, dll)) {
			return true;
		}
	}

	return false;
}

std::string EDR_Engine::hash_file(HANDLE hFile)
{
	BCRYPT_HASH_HANDLE hHash = NULL;


	// Compatible with windows 10 and higher!!!!
	NTSTATUS status = BCryptCreateHash(
		BCRYPT_SHA256_ALG_HANDLE,  // global pseudo-handle is used
		&hHash, NULL, 0, NULL, 0, 0
	);


	BYTE buffer[4096];
	DWORD bytesRead = 0;

	while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
		BCryptHashData(hHash, buffer, bytesRead, 0);
	}

	BYTE raw_hash[32] = { 0 };
	BCryptFinishHash(hHash, raw_hash, sizeof(raw_hash), 0);
	

	std::string hex_hash = "";

	for (auto byte : raw_hash) {
		char hex[3] = { 0 };
		sprintf_s(hex, "%02x", byte);
		hex_hash += hex;
	}
	puts("");

	// clean
	BCryptDestroyHash(hHash);
	return hex_hash;
}

void EDR_Engine::modify_entry_point(HANDLE hProc, LPVOID base_addr, DWORD file_size)
{
	if (file_size < sizeof(IMAGE_DOS_HEADER))
		return;

	BYTE* mem = (BYTE *)malloc(file_size);
	if (!mem)
		return;

	size_t readBytes = 0;

	if (ReadProcessMemory(hProc, base_addr, mem, file_size, &readBytes)) {
		
		PIMAGE_DOS_HEADER dos_head = (PIMAGE_DOS_HEADER)mem;

		if (dos_head->e_magic != IMAGE_DOS_SIGNATURE) {
			puts("magic check failed");
			free(mem);
			return;
		}

		PIMAGE_NT_HEADERS64 nt_header = (PIMAGE_NT_HEADERS64)(mem + dos_head->e_lfanew);
		
		if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
			puts("NT check failed");
			free(mem);
			return;
		}

		


		DWORD dll_entry_offset = nt_header->OptionalHeader.AddressOfEntryPoint;

		// if dll have no entry point
		if (dll_entry_offset == 0) {
			puts("dll entry is zero");
			free(mem);
			return;
		}


		LPVOID dll_entry_addr = (LPVOID)((char*)base_addr + dll_entry_offset);

		DWORD old_protect;
		VirtualProtectEx(hProc, dll_entry_addr, 1, PAGE_EXECUTE_READWRITE, &old_protect);
		if (WriteProcessMemory(hProc, dll_entry_addr, "\xc3", 1, NULL)) {
			std::cout << "	[SURGICAL REMEDIATION] Successfully patched entry point at: " << dll_entry_addr << "\n";
		}
	}

	free(mem);
	return;
}

void EDR_Engine::show_process_info() {
	puts("----------------------------------------------------");
	printf("The return value: %d with error %x\n", process_creation_status, GetLastError());
	printf("process handle: %p\n", pi.hProcess);
	printf("process ID: %d\n", pi.dwProcessId);
	puts("----------------------------------------------------");

	return;
}

EDR_Engine::~EDR_Engine() {
	free(si);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	ExitProcess(0);
}




