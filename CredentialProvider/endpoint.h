#ifndef _ENDPOINT_H
#define _ENDPOINT_H
#pragma once

#define _SECURE_SCL 0

/////////////////////////
/////////////////////// BASE ENDPOINT INCLUDES
/////////////////////////

#include "common.h"
#include "config.h"

/////////////////////////
/////////////////////// CONCRETE ENDPOINT INCLUDES
/////////////////////////

#ifdef _DEBUG
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif
#endif

/////////////////////////
/////////////////////// BASE ENDPOINT DECLARATIONS
/////////////////////////

namespace Endpoint
{
	#define ENDPOINT_TIMEOUT_SECS	90

	#define ENDPOINT_AUTH_OK		((HRESULT)0x78809001)
	#define ENDPOINT_AUTH_FAIL		((HRESULT)0x88809001)
	#define ENDPOINT_AUTH_CONTINUE	((HRESULT)0x88809002)

	enum ENDPOINT_STATUS 
	{
		NOT_READY		= 0,
		READY			= 1,
		FINISHED		= 2,
		NOT_FINISHED	= 3,
		WAITING			= 4,
		DATA_READY		= 5,
		SYNC_DATA		= 6,
		SHUTDOWN		= 7,
	};

	#define ENDPOINT_ERROR_MSG_SIZE 150
	#define ENDPOINT_INSTRUCTION_MSG_SIZE 150
	#define ENDPOINT_INFO_MSG_SIZE 150

	// TODO: dynamic data structure
	// !!! Match to concrete endpoint for project
	struct ENDPOINT
	{
		bool	protectMe = false; // Set to true, to protect from Deinit() and Default()

		//////

		wchar_t username[64];
		wchar_t otpPass[64];
		wchar_t ldapPass[64];

		wchar_t otpPass_2[64];
	};

	static ENDPOINT_STATUS STATUS = NOT_READY;
	static HRESULT LAST_ERROR_CODE = ENDPOINT_AUTH_FAIL;

	//static struct ENDPOINT_PACK *_epPck;

	ENDPOINT*& Get();
	void Default();
	void Init();
	void Deinit();
	HRESULT GetLastErrorCode();
	ENDPOINT_STATUS GetStatus();
	void GetLastErrorDescription(wchar_t (&error)[ENDPOINT_ERROR_MSG_SIZE]);
	void GetLastInstructionDescription(wchar_t(&msg)[ENDPOINT_INSTRUCTION_MSG_SIZE], bool *&big);
	void GetInfoMessage(wchar_t(&msg)[ENDPOINT_INFO_MSG_SIZE], long msg_code);
	void ShowInfoMessage(long msg_code);
	HRESULT Call();

	/////////////////////////
	/////////////////////// CONCRETE ENDPOINT DECLARATIONS
	/////////////////////////

	namespace Concrete
	{
		#define ENABLE_LOGGING true

		#define CEMOTP_PARAM_LOG    L"-log"
		#define CEMOTP_PARAM_RESYNC L"-resync"

		#define CEMOTP_EXIT_SUCCESS			0
		#define CEMOTP_EXIT_RESYNC_OK		14
		#define CEMOTP_EXIT_USER_NOT_FOUND	22
		#define CEMOTP_EXIT_ERROR_LOCKED	24
		#define CEMOTP_EXIT_ERROR_AUTH		99


		#define ENDPOINT_ERROR_WAIT_ABANDONED		((HRESULT)0x88809001)
		#define ENDPOINT_ERROR_WAIT_TIMEOUT			((HRESULT)0x88809003)
		#define ENDPOINT_ERROR_WAIT_FAILED			((HRESULT)0x88809004)

		#define ENDPOINT_ERROR_ACC_LOCKED			((HRESULT)0x88809101)
		#define ENDPOINT_ERROR_ACC_INVALID			((HRESULT)0x88809102)

		#define ENDPOINT_SUCCESS_WAIT_OBJECT_0		((HRESULT)0x78809001)
		#define ENDPOINT_SUCCESS_ACC_OK				((HRESULT)0x78809002)

		#define ENDPOINT_INFO_PLEASE_WAIT			((long)0x00000001)
		#define ENDPOINT_INFO_CALLING_ENDPOINT		((long)0x00000002)

		HRESULT CallExternalExe();
		HRESULT OTPCheckPassword();
		HRESULT OTPResync();
		HRESULT ExitCodeToHRESULT(DWORD exitCode);
	}
}

#endif
