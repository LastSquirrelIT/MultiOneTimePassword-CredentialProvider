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

#pragma once

#include <windows.h>

#define DllExport   __declspec( dllexport )
#define DllImport   __declspec( dllimport )

#define E_LOCKED  ((HRESULT)0x88808001)
#define E_INVALID ((HRESULT)0x88808002)

enum CMOTP_CES_PARAMETER
{
	CMOTP_CES_PARAMETER_FUNCTION	= 0,
	CMOTP_CES_PARAMETER_USERNAME	= 1,
	CMOTP_CES_PARAMETER_OTP_PASS_1	= 2,
	CMOTP_CES_PARAMETER_OTP_PASS_2	= 3
};

enum CMOTP_CES_FUNCTION
{
	CMOTP_CES_FUNCTION_AUTH		= 0,
	CMOTP_CES_FUNCTION_RESYNC	= 1
};

static const char CMOTP_CES_FUNCTION_VAL[] = 
{
	0,
	1
};

#ifdef EXPORTING
__interface DllExport IMultiOneTimePassword
#else
__interface DllImport IMultiOneTimePassword
#endif
{
	public:
		HRESULT Invoke(char *args[]);

		HRESULT __cdecl OTPCheckPassword(
			char *username, 
			char *otp
		);

		HRESULT __cdecl OTPResync(
			char *username, 
			char *otp1, 
			char *otp2
		);
};

#ifndef EXPORTING
class DllImport CMultiOneTimePassword : public IMultiOneTimePassword
{
	public:
		CMultiOneTimePassword(void);
		~CMultiOneTimePassword(void);

		HRESULT Invoke(char *args[]);

		HRESULT __cdecl OTPCheckPassword(
			char *username, 
			char *otp
		);

		HRESULT __cdecl OTPResync(
			char *username, 
			char *otp1, 
			char *otp2
		);
};
#endif

