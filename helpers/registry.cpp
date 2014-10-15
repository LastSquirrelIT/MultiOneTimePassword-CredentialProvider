#include "registry.h"

DWORD readRegistryValueString( __in int conf_value, __in int buffer_size, __deref_out_opt char* data ) {
	wchar_t lszValue[1024];
	HKEY hKey;
	LONG returnStatus;
	DWORD dwType = REG_SZ;
	DWORD dwSize = 0;

	PWSTR confValueName = s_CONF_VALUES[conf_value];

	returnStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = buffer_size;

		returnStatus = RegQueryValueEx(hKey, confValueName, NULL, &dwType,(LPBYTE)&lszValue, &dwSize);
		if (returnStatus == ERROR_SUCCESS)
		{
			WideCharToMultiByte(
				CP_ACP,
				0,
				lszValue,
				-1,
				data,
				dwSize, 
				NULL,
				NULL);
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

	PWSTR confValueName = s_CONF_VALUES[conf_value];

	returnStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_BASE_KEY, NULL, KEY_QUERY_VALUE, &hKey);
	if (returnStatus == ERROR_SUCCESS)
	{
		dwSize = sizeof(DWORD);

		returnStatus = RegQueryValueEx(hKey, confValueName, NULL, &dwType, reinterpret_cast<LPBYTE>(&lszValue), &dwSize);
		if (returnStatus == ERROR_SUCCESS)
		{
			*data = lszValue;
		}
		RegCloseKey(hKey);
	}

	return dwSize;
}
