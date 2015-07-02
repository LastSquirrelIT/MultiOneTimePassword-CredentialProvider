#include "registry.h"

DWORD readRegistryValueString( __in CONF_VALUE conf_value, __in int buffer_size, __deref_out_opt char* data) {
	//char lszValue[1024];
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_SZ;
	DWORD dwSize = 0;

	LPCSTR confValueName = s_CONF_VALUES[conf_value];

	returnStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = buffer_size;

		returnStatus = RegQueryValueExA(hKey, confValueName, NULL, &dwType,(LPBYTE)data, &dwSize);
		if (returnStatus != ERROR_SUCCESS)
		{
			dwSize = 0;
		}

		RegCloseKey(hKey);
	}

	return dwSize;
}

DWORD readRegistryValueInteger( __in CONF_VALUE conf_value, __deref_out_opt int* data ) {
	DWORD lszValue;
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = 0;

	LPCSTR confValueName = s_CONF_VALUES[conf_value];

	returnStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = sizeof(DWORD);

		returnStatus = RegQueryValueExA(hKey, confValueName, NULL, &dwType, reinterpret_cast<LPBYTE>(&lszValue), &dwSize);
		if (returnStatus == ERROR_SUCCESS)
		{
			*data = lszValue;
		}
		else
		{
			dwSize = 0;
		}

		RegCloseKey(hKey);
	}

	return dwSize;
}

DWORD writeRegistryValueString( __in CONF_VALUE conf_value, __in char* data, __in int buffer_size )
{
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_SZ;

	LPCSTR confValueName = s_CONF_VALUES[conf_value];

	returnStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus = RegSetKeyValueA(hKey, REGISTRY_BASE_KEY, confValueName, dwType, data, buffer_size);

		RegCloseKey(hKey);
	}

	return returnStatus;
}

DWORD writeRegistryValueInteger( __in CONF_VALUE conf_value, __in int data )
{
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_DWORD;

	LPCSTR confValueName = s_CONF_VALUES[conf_value];

	returnStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
	if (returnStatus == ERROR_SUCCESS)
	{
		returnStatus = RegSetKeyValueA(hKey, REGISTRY_BASE_KEY, confValueName, dwType, &data, sizeof(int));

		RegCloseKey(hKey);
	}

	return returnStatus;
}
