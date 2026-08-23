/*****************************************************************************
 * @file        communication.cpp
 * @brief       communication implementation
 * @author      Zied Sayari
 *
 * @details
 *	pipes communication
 *****************************************************************************/
#include "pch.h"
#include "communication.h"
#include <windows.h>
#include <strsafe.h>

void SendLogToEDR(const char* message) {
    const char* pipeName = "\\\\.\\pipe\\EDR_LogPipe";
    HANDLE hPipe = INVALID_HANDLE_VALUE;

    for (int i = 0; i < 5; i++) {
        hPipe = CreateFileA(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hPipe != INVALID_HANDLE_VALUE) break;

        if (GetLastError() == ERROR_PIPE_BUSY) {
            WaitNamedPipeA(pipeName, 100);
        }
        else {
            Sleep(10);
        }
    }

    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        // Sending raw ANSI string bytes
        WriteFile(hPipe, message, (DWORD)strlen(message), &bytesWritten, NULL);
        FlushFileBuffers(hPipe);
        CloseHandle(hPipe);
    }
}

void LogToEDR(const char* format, ...) {
    char buffer[512] = { 0 };

    va_list args;
    va_start(args, format);
    // Use StringCchVPrintfA instead of vsnprintf to stay in safe Win32 API boundaries
    StringCchVPrintfA(buffer, sizeof(buffer), format, args);
    va_end(args);

    SendLogToEDR(buffer);
}

int WstrToAnsi(PCWSTR wideStr, LPSTR ansiBuffer, int maxAnsiSize) {
    if (!wideStr || !ansiBuffer || maxAnsiSize <= 0) {
        return 0;
    }

    // Use Windows API to perform the conversion
    int charsConverted = WideCharToMultiByte(
        CP_ACP,                // Code page (ANSI)
        0,                     // Flags
        wideStr,               // Source wide string
        -1,                    // -1 means null-terminated string
        ansiBuffer,            // Destination narrow buffer
        maxAnsiSize,           // Size of destination buffer in bytes
        NULL,                  // Default character for unmapped chars
        NULL                   // Set to true if default char was used
    );

    return charsConverted;
}