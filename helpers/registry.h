#pragma once

#include "windows.h"
#include <winreg.h>
#include <stdio.h>

//#if !defined(_WIN64)
	#define REGISTRY_BASE_KEY L"SOFTWARE\\Last Squirrel IT\\MultiOTP"
//#else
//	#define REGISTRY_BASE_KEY L"SOFTWARE\\Wow6432Node\\Last Squirrel IT\\MultiOTP"
//#endif


enum CONF_VALUE
{
	CONF_PATH_TO_MULTIOTP	= 0,
	CONF_TIMEOUT			= 1,
	/*
	CONF_SERVER_URL			= 0,
	CONF_CLIENT_ID			= 1,
	CONF_DEFAULT_DOMAIN		= 2,
	CONF_USER_SETTINGS		= 3,
	CONF_CERT_FILE			= 4,
	CONF_CERT_PASSWORD		= 5,
	CONF_CA_FILE			= 6,
	CONF_LOGIN_TEXT			= 7,
	CONF_SOAP_TIMEOUT		= 8,
	CONF_NUM_VALUES			= 9,
	*/
};

static const PWSTR s_CONF_VALUES[] =
{
	L"path_to_multiotp",
	L"timeout"
	/*
	L"server_url",
	L"client_id",
	L"default_domain",
	L"user_settings",
	L"cert_file",
	L"cert_password",
	L"ca_file",
	L"login_text",
	L"soap_timeout",
	*/
};

DWORD readRegistryValueString( __in int conf_value, __in int buffer_size, __deref_out_opt char* data );
DWORD readRegistryValueInteger( __in CONF_VALUE conf_value, __deref_out_opt int* data );
