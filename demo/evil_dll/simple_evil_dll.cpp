// simple_evil_dll.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "simple_evil_dll.h"


// This is an example of an exported variable
SIMPLEEVILDLL_API int nsimpleevildll=0;

// This is an example of an exported function.
SIMPLEEVILDLL_API int fnsimpleevildll(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
Csimpleevildll::Csimpleevildll()
{
    return;
}
