/*****************************************************************************
 * @file        communication.cpp
 * @brief       communication header
 * @author      Zied Sayari
 * 
 * @details
 *	pipes communication
 *****************************************************************************/
#pragma once

void SendLogToEDR(const char* message);


// wrapper to make my life easier
void LogToEDR(const char* format, ...);


// util to print LdrLoadDll parameters
int WstrToAnsi(PCWSTR wideStr, LPSTR ansiBuffer, int maxAnsiSize);