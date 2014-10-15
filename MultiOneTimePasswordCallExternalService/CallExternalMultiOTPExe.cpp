/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright 2012 Dominik Pretzsch
** 
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
** 
**        http://www.apache.org/licenses/LICENSE-2.0
** 
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#include "CallExternalMultiOTPExe.h"

DWORD __CallMultiOTPExe(char* path_to_multiotp, int argc, wchar_t *argv[])
{
	DWORD exitCode = (DWORD)-1;

	const int SIZE = 200;
	wchar_t dir[SIZE] = L"";
	wchar_t cmd[SIZE] = CEMOTP_EXE;
	wchar_t app[SIZE] = L"";

	int timeout = DEFAULT_TIMEOUT_SEC;
	readRegistryValueInteger(CONF_TIMEOUT, &timeout);

	__CharToWideChar(path_to_multiotp, dir);

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("path_to_multiotp: "); OutputDebugStringA(path_to_multiotp); OutputDebugStringA("\n");	
	OutputDebugStringA("dir: "); OutputDebugStringW(dir); OutputDebugStringA("\n");	
	OutputDebugStringA("cmd: "); OutputDebugStringW(cmd); OutputDebugStringA("\n");
	//*/
#endif

	// Append the EXE to the path
	wcscat_s( app, SIZE, dir ); wcscat_s( app, SIZE, DIR_SEP ); wcscat_s( app, SIZE, cmd );

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("app: "); OutputDebugStringW(app); OutputDebugStringA("\n");
	//*/
#endif

	if (LOGGING) 
	{
		wcscat_s( cmd, SIZE, PARAM_SEP );
		wcscat_s( cmd, SIZE, CEMOTP_PARAM_LOG );
	}

	for (int i=0; i < argc; i++)
	{

#ifdef _DEBUG
		//*************************** DEBUG:
		OutputDebugStringA("argv[i]: "); OutputDebugStringW(argv[i]); OutputDebugStringA("\n");
		//*/
#endif

		wcscat_s( cmd, SIZE, PARAM_SEP );
		wcscat_s( cmd, SIZE, argv[i] );
	}

#ifdef _DEBUG
	__debugbreak();
#endif

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	SecureZeroMemory( &si, sizeof(si) );
	SecureZeroMemory( &pi, sizeof(pi) );

	si.cb = sizeof(si);

	if( ::CreateProcessW( app, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, dir, &si, &pi ) ) 
	{
		WaitForSingleObject( pi.hProcess, (timeout * 1000) );
		GetExitCodeProcess( pi.hProcess, &exitCode );

		CloseHandle( pi.hProcess );
		CloseHandle( pi.hThread );
	}

	// Clean up
	SecureZeroMemory( &si, sizeof(si) );
	SecureZeroMemory( &pi, sizeof(pi) );

	SecureZeroMemory((void*)app, SIZE);
	SecureZeroMemory((void*)cmd, SIZE);

	// BUG: Does not work (at least for x86)
	// TODO: Do conditional cleaning.
	/*
	for (int i=0; i<SIZE; i++)
		CoTaskMemFree((void*)app[i]);
	for (int i=0; i<SIZE; i++)
		CoTaskMemFree((void*)cmd[i]);
	*/

	return exitCode;
}
