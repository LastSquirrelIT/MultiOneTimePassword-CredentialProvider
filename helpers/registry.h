#ifndef _REGISTRY_H
#define _REGISTRY_H
#pragma once

#include "windows.h"
#include <winreg.h>
#include <stdio.h>

//#if !defined(_WIN64)
	#define REGISTRY_BASE_KEY "SOFTWARE\\Last Squirrel IT\\MultiOneTimePassword-CP"
//#else
//	#define REGISTRY_BASE_KEY L"SOFTWARE\\Wow6432Node\\Last Squirrel IT\\DUMMY-CP"
//#endif


enum CONF_VALUE
{
	CONF_PATH				  = 0,
	CONF_LOGIN_TEXT			  = 1,
	CONF_TIMEOUT			  = 2,
	CONF_NUM_VALUES			  = 3,
};

static const LPCSTR s_CONF_VALUES[] =
{
	"path",
	"login_text",
	"timeout"
};

DWORD readRegistryValueString( __in CONF_VALUE conf_value, __in int buffer_size, __deref_out_opt char* data);
DWORD readRegistryValueInteger( __in CONF_VALUE conf_value, __deref_out_opt int* data );

DWORD writeRegistryValueString( __in CONF_VALUE conf_value, __in char* data, __in int buffer_size);
DWORD writeRegistryValueInteger( __in CONF_VALUE conf_value, __in int data );

#endif
