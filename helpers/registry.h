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
	CONF_DEFAULT_DOMAIN     = 2,
};

static const PWSTR s_CONF_VALUES[] =
{
	L"path_to_multiotp",
	L"timeout",
	L"default_domain",
};

DWORD readRegistryValueString( __in int conf_value, __in int buffer_size, __deref_out_opt char* data );
DWORD readRegistryValueInteger( __in CONF_VALUE conf_value, __deref_out_opt int* data );
