/*
####################################################################
#                                                                  #
#                                                                  #
#    add the following line to your vmware vmx file to enable      #
#    "monitor control" backdoor:                                   #
#                                                                  #
#    isolation.monitor.control.disable = "FALSE"                   #
#                                                                  #
#                                                                  #
####################################################################
*/


#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <excpt.h>

int main(int argc, char* argv[])
{
	unsigned int subservice = 0;
	unsigned int value = 0;
	unsigned int result = 0;
	unsigned int code = 0;

	if(argc < 3)
		return printf("%s: <subservice no> <value>\nmissing argument.\n",argv[0]);

	subservice = atoi(argv[1]);
	value = atoi(argv[2]);

	__try
	{
		__asm
		{
			push eax
			push edx
			push ecx
			push ebx

			mov eax, 'VMXh'
			mov edx, 'VX'
			mov ecx, subservice
			shl ecx, 10h // upper 16 bit: subservice number for "monitor control" command
			or  ecx, 10h // lower 16 bit: backdoor service number for "monitor control" command (0x10)
			mov ebx, value // value to pass to "monitor control" subservice
			in  eax, dx

			mov result, eax
			mov code, ecx

			pop ebx
			pop ecx
			pop edx
			pop eax
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER)
	{
		printf("vmware backdoor not available.");
		return 0;
	}

	printf("result: %08X (eax), code: %08X (ecx)\n", result, code);

	return result;
}