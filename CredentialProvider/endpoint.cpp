#include "endpoint.h"

namespace Endpoint
{

/////////////////////////
/////////////////////// BASE ENDPOINT FUNCTIONALITY
/////////////////////////

ENDPOINT*& Get()
{
	static struct ENDPOINT *epPck = NULL;

	return epPck;
}

void Default()
{
	struct ENDPOINT*& epPck = Get();

	if (epPck == NULL || epPck->protectMe == true)
		return;

	ZERO(epPck->username);
	ZERO(epPck->otpPass);
	ZERO(epPck->ldapPass);

	ZERO(epPck->otpPass_2);
}

void Init()
{
	DebugPrintLn(__FUNCTION__);

	struct ENDPOINT*& epPck = Get();

	if (epPck == NULL /*|| (epPck != NULL && !epPck->protectMe)*/)
	{
		epPck = (struct ENDPOINT*) malloc(sizeof(struct ENDPOINT));

		STATUS = READY;
		epPck->protectMe = false;
	}
	
	Default();
}

void Deinit()
{
	DebugPrintLn(__FUNCTION__);

	struct ENDPOINT*& epPck = Get();

	Default();

	if (epPck != NULL && epPck->protectMe == false)
	{
		free(epPck);
		epPck = NULL;

		STATUS = NOT_READY;
	}
}

ENDPOINT_STATUS GetStatus()
{
	return STATUS;
}

HRESULT GetLastErrorCode()
{
	return LAST_ERROR_CODE;
}

void GetLastErrorDescription(wchar_t (&error)[ENDPOINT_ERROR_MSG_SIZE])
{
	DebugPrintLn(__FUNCTION__);

	//if (!SUCCEEDED(LAST_ERROR_CODE)) {
		switch ((int)LAST_ERROR_CODE) {
			// CheckJSONResponse
		case (int)ENDPOINT_ERROR_ACC_LOCKED:
			wcscpy_s(error, ARRAYSIZE(error), L"Your account has been locked. Please contact your system administrator.");
			break;
		case (int)ENDPOINT_ERROR_ACC_INVALID:
			wcscpy_s(error, ARRAYSIZE(error), L"You could not be authenticated. Wrong username or password?");
			break;
		default:
			break;
		}
	//}
}

void GetLastInstructionDescription(wchar_t(&msg)[ENDPOINT_INSTRUCTION_MSG_SIZE], bool *&big)
{
	DebugPrintLn(__FUNCTION__);

	UNREFERENCED_PARAMETER(msg);
	UNREFERENCED_PARAMETER(big);

	//if (SUCCEEDED(LAST_ERROR_CODE)) {
		switch ((int)LAST_ERROR_CODE) {
		case -1: // Nothing
		default:
			break;
		}
	//}
}

void GetInfoMessage(wchar_t(&msg)[ENDPOINT_INFO_MSG_SIZE], long msg_code)
{
	DebugPrintLn(__FUNCTION__);

	switch (msg_code) {
	case ENDPOINT_INFO_PLEASE_WAIT:
		wcscpy_s(msg, ARRAYSIZE(msg), L"Please wait...");
		break;
	case ENDPOINT_INFO_CALLING_ENDPOINT:
		wcscpy_s(msg, ARRAYSIZE(msg), L"Calling endpoint...");
		break;
	default:
		break;
	}
}

void ShowInfoMessage(long msg_code)
{
	DebugPrintLn(__FUNCTION__);

	if (Data::Credential::Get()->pqcws == NULL)
		return;

	wchar_t msg[ENDPOINT_INFO_MSG_SIZE];
	GetInfoMessage(msg, msg_code);

	Data::Credential::Get()->pqcws->SetStatusMessage(msg);
}

HRESULT Call()
{
	DebugPrintLn(__FUNCTION__);

	HRESULT result = ENDPOINT_AUTH_FAIL;

	// Do API call
	ShowInfoMessage(ENDPOINT_INFO_CALLING_ENDPOINT);

	struct ENDPOINT *epPack = Get();
	
	if (EMPTY(epPack->otpPass_2))
		LAST_ERROR_CODE = Concrete::OTPCheckPassword();
	else
		LAST_ERROR_CODE = Concrete::OTPResync();

	ShowInfoMessage(ENDPOINT_INFO_PLEASE_WAIT);

	// TRANSLATE HRESULT TO BASE DEFINITIONS
	if (LAST_ERROR_CODE == ENDPOINT_SUCCESS_ACC_OK)
	{
		DebugPrintLn("Verification successfull :)");

		result = ENDPOINT_AUTH_OK; // Default success code

		STATUS = FINISHED;

		if (NOT_EMPTY(epPack->otpPass_2))
			Data::General::Get()->bypassKerberos = true;
	}
	else
	{
		DebugPrintLn("Verification failed :(");

		STATUS = FINISHED;

		if (NOT_EMPTY(epPack->otpPass_2))
			Data::General::Get()->bypassKerberos = true;
	}

	return result;
}  


/////////////////////////
/////////////////////// CONCRETE ENDPOINT FUNCTIONALITY
/////////////////////////

namespace Concrete
{

	HRESULT CallExternalExe(int argc, wchar_t *argv[])
	{
		DWORD exitCode = (DWORD)-1;

		HRESULT hr = E_FAIL;

		const int SIZE = 200;
		wchar_t dir[SIZE] = L"";
		wchar_t cmd[SIZE] = L"multiotp.exe";
		wchar_t app[SIZE] = L"";

		//int timeout = ENDPOINT_TIMEOUT_SECS;
		//readRegistryValueInteger(CONF_TIMEOUT, &timeout);

		DebugPrintLn("Path to multiOTP.exe:");
		DebugPrintLn(Configuration::Get()->path);

		Helper::CharToWideChar(Configuration::Get()->path, sizeof(dir) / sizeof(wchar_t), dir);

		// Append the EXE to the path
		wcscat_s(app, SIZE, dir); wcscat_s(app, SIZE, L"/"); wcscat_s(app, SIZE, cmd);

		DebugPrintLn("Path to multiOTP.exe (executable):");
		DebugPrintLn(app);

		#pragma warning(disable:4127)  
		if (ENABLE_LOGGING)
		{
			DebugPrintLn("Logging enabled");

			wcscat_s(cmd, SIZE, L" ");
			wcscat_s(cmd, SIZE, CEMOTP_PARAM_LOG);
		}

		for (int i = 0; i < argc; i++)
		{

			DebugPrintLn("Adding argument:");
			DebugPrintLn(argv[i]);

			wcscat_s(cmd, SIZE, L" ");
			wcscat_s(cmd, SIZE, argv[i]);
		}

		STARTUPINFO si;
		PROCESS_INFORMATION pi;

		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);

		if (::CreateProcessW(app, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, dir, &si, &pi))
		{
			DebugPrintLn("Calling multiOTP.exe ...");

			DWORD result = WaitForSingleObject(pi.hProcess, (Configuration::Get()->timeout * 1000));

			/*
			Return values:
			  WAIT_ABANDONED
			  WAIT_OBJECT_0
			  WAIT_TIMEOUT
			  WAIT_FAILED
			*/

			switch (result)
			{
			case WAIT_ABANDONED:
				hr = ENDPOINT_ERROR_WAIT_ABANDONED;
				break;
			case WAIT_OBJECT_0:
				hr = ENDPOINT_SUCCESS_WAIT_OBJECT_0;
				break;
			case WAIT_TIMEOUT:
				hr = ENDPOINT_ERROR_WAIT_TIMEOUT;
				break;
			case WAIT_FAILED:
				hr = ENDPOINT_ERROR_WAIT_FAILED;
				break;
			default:
				hr = E_FAIL;
				break;
			}			

			DebugPrintLn("WaitForSingleObject result:");
			DebugPrintLn(result);

			GetExitCodeProcess(pi.hProcess, &exitCode);

			DebugPrintLn("multiOTP.exe Exit Code:");
			DebugPrintLn(exitCode);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}
		else
		{
			DebugPrintLn("Could not call multiOTP.exe ...");
		}

		// Clean up
		SecureZeroMemory(&si, sizeof(si));
		SecureZeroMemory(&pi, sizeof(pi));

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

		if (FAILED(hr))
			return hr;

		return ExitCodeToHRESULT(exitCode);

		//return exitCode;
	}

	HRESULT OTPCheckPassword()
	{
		const int argc = 2;
		wchar_t *argv[argc];

		struct ENDPOINT *epPack = Get();

		argv[0] = epPack->username;
		argv[1] = epPack->otpPass;

		DebugPrintLn("Username:");
		DebugPrintLn(epPack->username);
		DebugPrintLn("OTP:");
		DebugPrintLn(epPack->otpPass);

		HRESULT hr = CallExternalExe(argc, argv);

		for (int i = 0; i<argc; i++)
		{
			argv[i] = NULL;
			CoTaskMemFree(argv[i]);
		}

		return hr;
	}

	HRESULT OTPResync()
	{
		const int argc = 4;
		wchar_t *argv[argc];

		wchar_t *resync = CEMOTP_PARAM_RESYNC;

		struct ENDPOINT *epPack = Get();

		argv[0] = resync;
		argv[1] = epPack->username;
		argv[2] = epPack->otpPass;
		argv[3] = epPack->otpPass_2;

		DebugPrintLn("Username:");
		DebugPrintLn(epPack->username);
		DebugPrintLn("OTP #1:");
		DebugPrintLn(epPack->otpPass);
		DebugPrintLn("OTP #2:");
		DebugPrintLn(epPack->otpPass_2);

		HRESULT hr = CallExternalExe(argc, argv);

		for (int i = 0; i<argc; i++)
		{
			argv[i] = NULL;
			CoTaskMemFree(argv[i]);
		}

		return hr;
	}

	HRESULT ExitCodeToHRESULT(DWORD exitCode)
	{
		switch (exitCode) {
		case CEMOTP_EXIT_SUCCESS:
		case CEMOTP_EXIT_RESYNC_OK:
			return ENDPOINT_SUCCESS_ACC_OK;
			break;
		case CEMOTP_EXIT_ERROR_LOCKED:
			return ENDPOINT_ERROR_ACC_LOCKED;
			break;
		case CEMOTP_EXIT_ERROR_AUTH:
		case CEMOTP_EXIT_USER_NOT_FOUND:
			return ENDPOINT_ERROR_ACC_INVALID;
			break;
		default:
			return E_FAIL;
			break;
		}
	}

} // Namespace Concrete

} // Namespace Endpoint
