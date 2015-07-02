#include "config.h"

namespace Configuration
{

CONFIGURATION*& Get()
{
	static struct CONFIGURATION *conf = NULL;

	return conf;
}

void Default()
{
	struct CONFIGURATION*& conf = Get();

	ZERO(conf->path);
	ZERO(conf->login_text);

	conf->timeout = 0;
}

void Init()
{
	DebugPrintLn(__FUNCTION__);

	struct CONFIGURATION*& conf = Get();

	conf = (struct CONFIGURATION*) malloc(sizeof(struct CONFIGURATION));

	Default();
}

void Deinit()
{
	DebugPrintLn(__FUNCTION__);

	struct CONFIGURATION*& conf = Get();

	Default();

	free(conf);
	conf = NULL;
}

///////////////////// SPECIFIC CONFIGURATION

void Read()
{
	DebugPrintLn(__FUNCTION__);

	struct CONFIGURATION*& conf = Get();

	// Read config
	readRegistryValueString(CONF_PATH, sizeof(conf->path), conf->path);

	if (readRegistryValueString(CONF_LOGIN_TEXT, sizeof(conf->login_text), conf->login_text) <= 1) // 1 = size of a char NULL-terminator in byte
		strcpy_s(conf->login_text, sizeof(conf->login_text), CONFIG_DEFAULT_LOGIN_TEXT);

	if(readRegistryValueInteger(CONF_TIMEOUT, &conf->timeout) == 0 || conf->timeout == 0)
		conf->timeout = CONFIG_DEFAULT_TIMEOUT_IN_SECS;
	// END
}

DWORD SaveValueString(CONF_VALUE conf_value, char* value, int size)
{
	DebugPrintLn(__FUNCTION__);

	return writeRegistryValueString(conf_value, value, size);
}

DWORD SaveValueInteger(CONF_VALUE conf_value, int value)
{
	DebugPrintLn(__FUNCTION__);

	return writeRegistryValueInteger(conf_value, value);
}

} // Namespace Configuration