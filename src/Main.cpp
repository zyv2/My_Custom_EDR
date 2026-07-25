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