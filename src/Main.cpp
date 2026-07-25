/*****************************************************************************
 * @file        Main.cpp
 * @brief       My_Custom_EDR main function
 * @author      Zied Sayari
 * 
 *
 * @details
 * Evolving user-mode Endpoint Detection and Response prototype. Implements
 * low-level Windows Debugging APIs to intercept injected modules, safely
 * parse Portable Executable (PE) headers, and execute surgical inline memory
 * patching (ret) to force safe initialization failure.
 *****************************************************************************/

#include <Windows.h>
#include <iostream>
#include "EDR_Engine.h"
#include <string>

int main(int argc, char **argv) {

	if (argc < 2) {
		std::cout << "Usage : EDR <target prgram>" << std::endl;
	}
	else
	{
		
		EDR_Engine edr(argv[1]);
		edr.show_process_info();
		edr.monitor();

	}


	return 0;
}