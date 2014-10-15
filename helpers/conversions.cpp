#include "conversions.h"

void __WideCharToChar(
		__in  wchar_t* data,
		__in  int      buffSize,
		__out char*    pc
	 )
{
	WideCharToMultiByte(
		CP_ACP,
		0,
		data,
		-1,
		pc,
		buffSize, 
		NULL,
		NULL);
}

void __CharToWideChar(
		__in  char*		data,
		__in  int       buffSize,
		__out wchar_t*  pc
	 )
{
	int size = buffSize;
	if (!buffSize)
		size = MultiByteToWideChar(CP_ACP, 0, data, -1, pc, 0);
	MultiByteToWideChar(CP_ACP, 0, data, -1, pc, size);
}

void __CharToWideChar(
		__in  char*		data,
		__out wchar_t*  pc
	 )
{
	__CharToWideChar(data, 0, pc);
}