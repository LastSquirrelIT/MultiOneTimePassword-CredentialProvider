#ifndef _CONFIG_H
#define _CONFIG_H
#pragma once

//#include "dependencies.h"

#include "common.h"
#include "helper.h"
#include "registry.h"

namespace Configuration
{
	#define CONFIG_DEFAULT_LOGIN_TEXT "MultiOTP Login"

	#define CONFIG_DEFAULT_TIMEOUT_IN_SECS 60

	/////////////////// BASE

	struct CONFIGURATION
	{
		char path[1024];
		char login_text[64];
		int timeout;
	};

	CONFIGURATION*& Get();
	void Default();
	void Init();
	void Deinit();

	////////////////// SPECIFIC

	void Read();
	DWORD SaveValueString(CONF_VALUE conf_value, char* value, int size);
	DWORD SaveValueInteger(CONF_VALUE conf_value, int value);
}

#endif
