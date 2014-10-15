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

#include "CMultiOneTimePasswordImpl.h"


CMultiOneTimePassword::CMultiOneTimePassword(void)
	: i(0)
{
}

CMultiOneTimePassword::~CMultiOneTimePassword(void)
{
}

HRESULT CMultiOneTimePassword::Invoke(char *args[])
{
#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("function: "); OutputDebugStringA(args[CMOTP_CES_PARAMETER_FUNCTION]); OutputDebugStringA("\n");	
	OutputDebugStringA("username: "); OutputDebugStringA(args[CMOTP_CES_PARAMETER_USERNAME]); OutputDebugStringA("\n");	
	OutputDebugStringA("otp1: "); OutputDebugStringA(args[CMOTP_CES_PARAMETER_OTP_PASS_1]); OutputDebugStringA("\n");
	OutputDebugStringA("otp2: "); OutputDebugStringA(args[CMOTP_CES_PARAMETER_OTP_PASS_2]); OutputDebugStringA("\n");
	//*/
#endif

	HRESULT hr = E_FAIL;
	if (*args[CMOTP_CES_PARAMETER_FUNCTION] == CMOTP_CES_FUNCTION_AUTH)
	{
		hr = OTPCheckPassword(args[CMOTP_CES_PARAMETER_USERNAME], args[CMOTP_CES_PARAMETER_OTP_PASS_1]);
	}
	else if (*args[CMOTP_CES_PARAMETER_FUNCTION] == CMOTP_CES_FUNCTION_RESYNC)
	{
		hr = OTPResync(args[CMOTP_CES_PARAMETER_USERNAME], args[CMOTP_CES_PARAMETER_OTP_PASS_1], args[CMOTP_CES_PARAMETER_OTP_PASS_2]);
	}
	return hr;
}

HRESULT CMultiOneTimePassword::OTPCheckPassword(
	char *username, 
	char *otp
	)
{
	/* DEBUGGING:
	return E_FAIL;
	//*/

	char path_to_multiotp[512];
	readRegistryValueString(CONF_PATH_TO_MULTIOTP, sizeof(path_to_multiotp), path_to_multiotp);

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("username: "); OutputDebugStringA(username); OutputDebugStringA("\n");	
	OutputDebugStringA("otp: "); OutputDebugStringA(otp); OutputDebugStringA("\n");	
	//*/
#endif

	wchar_t wc_username[64] = L"", wc_otp[64] = L"";

	const int argc = 2;	
	wchar_t *argv[argc];

	__CharToWideChar(username, wc_username);
	__CharToWideChar(otp, wc_otp);

	argv[0] = wc_username;
	argv[1] = wc_otp;

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("wc_username: "); OutputDebugStringW(wc_username); OutputDebugStringA("\n");	
	OutputDebugStringA("wc_otp: "); OutputDebugStringW(wc_otp); OutputDebugStringA("\n");	
	OutputDebugStringA("argv[0]: "); OutputDebugStringW(argv[0]); OutputDebugStringA("\n");
	OutputDebugStringA("argv[1]: "); OutputDebugStringW(argv[1]); OutputDebugStringA("\n");
	//*/
#endif

	HRESULT hr = _MultiOTPExitCodeToHRESULT( __CallMultiOTPExe(path_to_multiotp, argc, argv) );

	OutputDebugStringA("back from call"); OutputDebugStringA("\n");

	for (int i=0; i<argc; i++)
	{
		argv[i] = NULL;
		CoTaskMemFree(argv[i]);
	}

	OutputDebugStringA("everything nice and clean"); OutputDebugStringA("\n");

	return hr;
}

HRESULT CMultiOneTimePassword::OTPResync(
	char *username, 
	char *otp1, 
	char *otp2
	)
{
	char path_to_multiotp[512];
	readRegistryValueString(CONF_PATH_TO_MULTIOTP, sizeof(path_to_multiotp), path_to_multiotp);

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("username: "); OutputDebugStringA(username); OutputDebugStringA("\n");	
	OutputDebugStringA("otp1: "); OutputDebugStringA(otp1); OutputDebugStringA("\n");
	OutputDebugStringA("otp2: "); OutputDebugStringA(otp2); OutputDebugStringA("\n");	
	//*/
#endif

	wchar_t wc_username[64] = L"", wc_otp1[64] = L"", wc_otp2[64] = L"";

	const int argc = 4;	
	wchar_t *argv[argc];

	wchar_t *resync = CEMOTP_PARAM_RESYNC;

	__CharToWideChar(username, wc_username);
	__CharToWideChar(otp1, wc_otp1);
	__CharToWideChar(otp2, wc_otp2);

	argv[0] = resync;
	argv[1] = wc_username;
	argv[2] = wc_otp1;
	argv[3] = wc_otp2;

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("wc_username: "); OutputDebugStringW(wc_username); OutputDebugStringA("\n");	
	OutputDebugStringA("wc_otp1: "); OutputDebugStringW(wc_otp1); OutputDebugStringA("\n");
	OutputDebugStringA("wc_otp2: "); OutputDebugStringW(wc_otp2); OutputDebugStringA("\n");	
	OutputDebugStringA("argv[0]: "); OutputDebugStringW(argv[0]); OutputDebugStringA("\n");	
	OutputDebugStringA("argv[1]: "); OutputDebugStringW(argv[1]); OutputDebugStringA("\n");
	OutputDebugStringA("argv[2]: "); OutputDebugStringW(argv[2]); OutputDebugStringA("\n");
	//*/
#endif
	
	HRESULT hr = _MultiOTPExitCodeToHRESULT( __CallMultiOTPExe(path_to_multiotp, argc, argv) );

	OutputDebugStringA("back from call"); OutputDebugStringA("\n");

	for (int i=0; i<argc; i++)
	{
		argv[i] = NULL;
		CoTaskMemFree(argv[i]);
	}

	OutputDebugStringA("everything nice and clean"); OutputDebugStringA("\n");

	return hr;
}


HRESULT CMultiOneTimePassword::_MultiOTPExitCodeToHRESULT(DWORD exitCode)
{
	switch (exitCode) {
		case CEMOTP_EXIT_SUCCESS:
		case CEMOTP_EXIT_RESYNC_OK:
			return S_OK;
			break;
		case CEMOTP_EXIT_ERROR_LOCKED:
			return E_LOCKED;
			break;
		case CEMOTP_EXIT_ERROR_AUTH:
			return E_INVALID;
			break;
		default:
			return E_FAIL;
			break;
	}
}
