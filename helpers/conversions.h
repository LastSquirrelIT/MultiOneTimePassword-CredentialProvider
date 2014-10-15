#include <windows.h>

void __WideCharToChar(
		__in  wchar_t* data,
		__in  int      buffSize,
		__out char*    pc
	 );

void __CharToWideChar(
		__in  wchar_t* data,
		__in  int      buffSize,
		__out char*    pc
	 );

void __CharToWideChar(
		__in  char*		data,
		__out wchar_t*  pc
	 );