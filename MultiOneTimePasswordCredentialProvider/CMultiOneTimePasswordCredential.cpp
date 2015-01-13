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

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>

#include "CMultiOneTimePasswordCredential.h"
#include "CWrappedCredentialEvents.h"
#include "guid.h"

// CMultiOneTimePasswordCredential ////////////////////////////////////////////////////////

CMultiOneTimePasswordCredential::CMultiOneTimePasswordCredential():
    _cRef(1),
    _pCredProvCredentialEvents(NULL),
	_user_name(NULL),
	_domain_name(NULL),
	_forced_password_change(0),
	_password_buffer(NULL)
{
    DllAddRef();

    ZERO(_rgCredProvFieldDescriptors);
    ZERO(_rgFieldStatePairs);
    ZERO(_rgFieldStrings);
	ZERO(_default_login_text);

	ZERO(_default_domain);

	strcpy_s(_default_login_text, sizeof(_default_login_text), DEFAULT_LOGIN_TEXT);

	// Read OpenOTP config
	readRegistryValueString(CONF_DEFAULT_DOMAIN, sizeof(_default_domain), _default_domain);
}

CMultiOneTimePasswordCredential::~CMultiOneTimePasswordCredential()
{
    if (_rgFieldStrings[SFI_OTP_USERNAME])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenUsername = lstrlen(_rgFieldStrings[SFI_OTP_USERNAME]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_USERNAME], lenUsername * sizeof(*_rgFieldStrings[SFI_OTP_USERNAME]));
    }
    if (_rgFieldStrings[SFI_OTP_LDAP_PASS])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS]));
    }
	if (_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]));
    }
	if (_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]));
    }
	if (_rgFieldStrings[SFI_OTP_PASS])
    {
        // CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_PASS]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CMultiOneTimePasswordCredential::Initialize(
	__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, 
    __in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    __in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name
    )
{
    HRESULT hr = S_OK;

	_cpus = cpus;

	if (user_name)
		_user_name = user_name;

	if (domain_name)
		_domain_name = domain_name;

    // Copy the field descriptors for each field. This is useful if you want to vary the 
    // field descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String values of all the fields.
	if (SUCCEEDED(hr))
    {
		//if (_openotp_login_text[0] == NULL)
		//	hr = SHStrDupW(OPENOTP_DEFAULT_LOGIN_TEXT, &_rgFieldStrings[SFI_OTP_LARGE_TEXT]);
		//else
		//{
			wchar_t large_text[sizeof(_default_login_text)];

			int size = MultiByteToWideChar(CP_ACP, 0, _default_login_text, -1, large_text, 0);
			MultiByteToWideChar(CP_ACP, 0, _default_login_text, -1, large_text, size);

			hr = SHStrDupW(large_text, &_rgFieldStrings[SFI_OTP_LARGE_TEXT]);
		//}

		//hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LARGE_TEXT]);
    }
	if (SUCCEEDED(hr))
    {
		if (_cpus == CPUS_UNLOCK_WORKSTATION)
			hr = SHStrDupW(WORKSTATION_LOCKED, &_rgFieldStrings[SFI_OTP_SMALL_TEXT]);
		else if (_cpus == CPUS_CHANGE_PASSWORD)
			hr = SHStrDupW(CHANGE_PASSWORD, &_rgFieldStrings[SFI_OTP_SMALL_TEXT]);
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_SMALL_TEXT]);
	}
    if (SUCCEEDED(hr))
    {
		if ((_cpus == CPUS_UNLOCK_WORKSTATION || _cpus == CPUS_CHANGE_PASSWORD) && _user_name)
		{
			hr = SHStrDupW(_user_name, &_rgFieldStrings[SFI_OTP_USERNAME]);
		}
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS]);
    }
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
    }
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]);
    }
	if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_PASS]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_OTP_SUBMIT_BUTTON]);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CMultiOneTimePasswordCredential::Advise(
    __in ICredentialProviderCredentialEvents* pcpce
    )
{
    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CMultiOneTimePasswordCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions. In fact, we're just going to hand it off to the
// wrapped credential in case it wants to do something.
HRESULT CMultiOneTimePasswordCredential::SetSelected(__out BOOL* pbAutoLogon)  
{
    *pbAutoLogon = FALSE;  

	if (_forced_password_change)
	{
		if (_forced_password_change == 1)
			_SetFieldScenario(SCENARIO_CHANGE_PASSWORD);
		else if (_forced_password_change == 2)
			*pbAutoLogon = TRUE;
		else
		{
			if (_cpus == CPUS_UNLOCK_WORKSTATION)
				_SetFieldScenario(SCENARIO_UNLOCK_BASE);
			else if (_cpus == CPUS_LOGON)
				_SetFieldScenario(SCENARIO_LOGON_BASE);

			_forced_password_change = 0;
		}
	}

    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. We'll let the wrapped credential do anything it needs.
HRESULT CMultiOneTimePasswordCredential::SetDeselected()
{
    HRESULT hr = S_OK;
	if (!(_cpus == CPUS_UNLOCK_WORKSTATION || _cpus == CPUS_CHANGE_PASSWORD) && _rgFieldStrings[SFI_OTP_USERNAME])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_USERNAME]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_USERNAME], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_USERNAME]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_USERNAME]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_USERNAME]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_USERNAME, _rgFieldStrings[SFI_OTP_USERNAME]);
        }
    }

	_CleanPasswordFields();

	if (_cpus == CPUS_UNLOCK_WORKSTATION)
		_SetFieldScenario(SCENARIO_UNLOCK_BASE);
	else if (_cpus == CPUS_CHANGE_PASSWORD)
		_SetFieldScenario(SCENARIO_CHANGE_PASSWORD);
	else
		_SetFieldScenario(SCENARIO_LOGON_BASE);

	_forced_password_change = 0; // In case user selects to abort the change or another user wants to logon

    return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CMultiOneTimePasswordCredential::GetFieldState(
    __in DWORD dwFieldID,
    __out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    __out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    HRESULT hr;

    // Validate paramters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;

        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CMultiOneTimePasswordCredential::GetStringValue(
    __in DWORD dwFieldID, 
    __deref_out PWSTR* ppwsz
    )
{
    HRESULT hr;

    // Check to make sure dwFieldID is a legitimate index.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz) 
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Gets the image to show in the user tile.
HRESULT CMultiOneTimePasswordCredential::GetBitmapValue(
    __in DWORD dwFieldID, 
    __out HBITMAP* phbmp
    )
{
    HRESULT hr;
    if ((SFI_OTP_LOGO == dwFieldID) && phbmp)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != NULL)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CMultiOneTimePasswordCredential::GetSubmitButtonValue(
    __in DWORD dwFieldID,
    __out DWORD* pdwAdjacentTo
    )
{
    HRESULT hr;

    // Validate parameters.
    if ((SFI_OTP_SUBMIT_BUTTON == dwFieldID) && pdwAdjacentTo)
    {
        // pdwAdjacentTo is a pointer to the fieldID you want the submit button to appear next to.
        *pdwAdjacentTo = SFI_OTP_PASS;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CMultiOneTimePasswordCredential::SetStringValue(
    __in DWORD dwFieldID, 
    __in PCWSTR pwz      
    )
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && 
       (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft || 
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft)) 
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CMultiOneTimePasswordCredential::GetCheckboxValue(
    __in DWORD dwFieldID, 
    __out BOOL* pbChecked,
    __deref_out PWSTR* ppwszLabel
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT CMultiOneTimePasswordCredential::GetComboBoxValueCount(
    __in DWORD dwFieldID, 
    __out DWORD* pcItems, 
    __out_range(<,*pcItems) DWORD* pdwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CMultiOneTimePasswordCredential::GetComboBoxValueAt(
    __in DWORD dwFieldID, 
    __in DWORD dwItem,
    __deref_out PWSTR* ppwszItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT CMultiOneTimePasswordCredential::SetCheckboxValue(
    __in DWORD dwFieldID, 
    __in BOOL bChecked
    )
{
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT CMultiOneTimePasswordCredential::SetComboBoxSelectedValue(
    __in DWORD dwFieldId,
    __in DWORD dwSelectedItem
    )
{
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CMultiOneTimePasswordCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//

void CMultiOneTimePasswordCredential::_SeparateUserAndDomainName(
	__in wchar_t *domain_slash_username,
	__out wchar_t *username,
	__in int sizeUsername,
	__out_opt wchar_t *domain,
	__in_opt int sizeDomain
	)
{
	int pos;
	for(pos=0;domain_slash_username[pos]!=L'\\' && domain_slash_username[pos]!=NULL;pos++);

	if (domain_slash_username[pos]!=NULL)
	{
		int i;
		for (i=0;i<pos && i<sizeDomain;i++)
			domain[i] = domain_slash_username[i];
		domain[i]=L'\0';

		for (i=0;domain_slash_username[pos+i+1]!=NULL && i<sizeUsername;i++)
			username[i] = domain_slash_username[pos+i+1];
		username[i]=L'\0';
	}
	else
	{
		int i;
		for (i=0;i<pos && i<sizeUsername;i++)
			username[i] = domain_slash_username[i];
		username[i]=L'\0';
	}
}

void CMultiOneTimePasswordCredential::_CleanPasswordFields()
{
	HRESULT hr;

	if (_rgFieldStrings[SFI_OTP_LDAP_PASS])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LDAP_PASS, _rgFieldStrings[SFI_OTP_LDAP_PASS]);
        }
    }
	if (_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LDAP_PASS_NEW_1, _rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
        }
    }
	if (_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LDAP_PASS_NEW_2, _rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]);
        }
    }
    if (_rgFieldStrings[SFI_OTP_PASS])
    {
        size_t lenPassword = lstrlen(_rgFieldStrings[SFI_OTP_PASS]);
        SecureZeroMemory(_rgFieldStrings[SFI_OTP_PASS], lenPassword * sizeof(*_rgFieldStrings[SFI_OTP_PASS]));
    
        CoTaskMemFree(_rgFieldStrings[SFI_OTP_PASS]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OTP_PASS]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_PASS, _rgFieldStrings[SFI_OTP_PASS]);
        }
    }
}

//
// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
//
HRESULT CMultiOneTimePasswordCredential::GetSerialization(
    __out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
	HRESULT otpCheck, hr = E_UNEXPECTED;

	INIT_ZERO_WCHAR(username, 64);
	INIT_ZERO_WCHAR(domain, 64);

	wchar_t *user_input = _wcsdup(_rgFieldStrings[SFI_OTP_USERNAME]);
	INIT_ZERO_WCHAR(temp, (sizeof(domain) + sizeof(L'\\') + sizeof(username)) / sizeof(wchar_t)); // domain + \ + username

#ifdef _DEBUG
	//*************************** DEBUG:
	char code[1024];
	OutputDebugStringA("user_input:\t\t"); OutputDebugStringW(user_input); OutputDebugStringA("\n");	
	OutputDebugStringA("default domain:\t\t"); OutputDebugStringA(_default_domain); OutputDebugStringA("\n");
	//*/
#endif

	if (wcsstr(user_input, L"localhost\\") == NULL && _cpus == CPUS_LOGON) 
	{
#ifdef _DEBUG
		//*************************** DEBUG:
		OutputDebugStringA("not localhost\\\\*"); OutputDebugStringA("\n");	
		//*/
#endif

		if (wcsstr(user_input, L"\\") == NULL && _default_domain && _default_domain[0]) 
		{
#ifdef _DEBUG
			//*************************** DEBUG:
			OutputDebugStringA("no domain specified"); OutputDebugStringA("\n");	
			//*/
#endif
			__CharToWideChar(_default_domain, sizeof(temp) / sizeof(wchar_t), temp);

			wcscat_s(temp, sizeof(temp) / sizeof(wchar_t), L"\\");
			wcscat_s(temp, sizeof(temp) / sizeof(wchar_t), user_input);

			user_input = temp;
		}

		_SeparateUserAndDomainName(user_input, username, sizeof(username) / sizeof(wchar_t), domain, sizeof(domain) / sizeof(wchar_t));
	} 
	else 
	{
		_SeparateUserAndDomainName(user_input, username, sizeof(username) / sizeof(wchar_t), domain, sizeof(domain) / sizeof(wchar_t));

		ZERO (domain); // because "localhost" is no domain, so the computer-name will be fetched (later)
	}

	// Set domain name:
	if (domain[0])
		// ... user typed DOMAIN\USERNAME, so we set it to DOMAIN
		_domain_name = _wcsdup(domain);

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("user:\t\t"); OutputDebugStringW(username); OutputDebugStringA("\n");	
	OutputDebugStringA("domain:\t\t"); OutputDebugStringW(domain); OutputDebugStringA("\n");
	OutputDebugStringA("ldap:\t\t"); OutputDebugStringW(_rgFieldStrings[SFI_OTP_LDAP_PASS]); OutputDebugStringA("\n");
	OutputDebugStringA("ldap (new):\t"); OutputDebugStringW(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]); OutputDebugStringA("\n");
	OutputDebugStringA("ldap (buff):\t"); OutputDebugStringW(_password_buffer); OutputDebugStringA("\n");
	//*/
#endif

	// CPUS_CHANGE_PASSWORD:
	if (_cpus == CPUS_CHANGE_PASSWORD || _forced_password_change == 1) {
		if (StrCmp(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1], _rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_2]) == 0)
			hr = _DoKerberosChangePassword(pcpgsr, pcpcs, username, _rgFieldStrings[SFI_OTP_LDAP_PASS], _rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);
		else
			hr = E_FAIL;

		if (SUCCEEDED(hr))
		{
			hr = S_OK;
			if (_forced_password_change == 1)
			{				
				//SHStrDupW(L"Password successfully changed.", ppwszOptionalStatusText);						
				//*pcpsiOptionalStatusIcon = CPSI_SUCCESS;
				//*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

				_password_buffer = _wcsdup(_rgFieldStrings[SFI_OTP_LDAP_PASS_NEW_1]);

				_forced_password_change = 2;
			}
		}
		else
		{
			hr = S_FALSE;
			SHStrDupW(L"Your password could not be changed. Make sure you typed your new password twice.", ppwszOptionalStatusText);									
			*pcpsiOptionalStatusIcon = CPSI_ERROR;
			*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
		}

		goto CleanUpAndReturn;
	}    

	// CPUS_UNLOCK_WORKSTATION:
	// CPUS_LOGON:

	otpCheck = _CheckOtp(username, _rgFieldStrings[SFI_OTP_PASS]);

#ifdef _DEBUG
	otpCheck = S_OK;
#endif

	if (SUCCEEDED(otpCheck))
	{
		if (_forced_password_change == 2)
		{
			hr = _DoKerberosLogon(pcpgsr, pcpcs, username, _password_buffer);	

			// TODO: Move to better position
			//size_t lenPassword = lstrlen(_password_buffer);
			//SecureZeroMemory(_password_buffer, lenPassword * sizeof(*_password_buffer));
    
			//CoTaskMemFree(_password_buffer);
			hr = SHStrDupW(L"", &_password_buffer);

			_forced_password_change = 3;
		}
		else
			hr = _DoKerberosLogon(pcpgsr, pcpcs, username, _rgFieldStrings[SFI_OTP_LDAP_PASS]);
		//goto CleanUpAndReturn;
	}
	else
	{
		switch (otpCheck) {
			case E_FAIL:
			case E_INVALID:
				SHStrDupW(I18N_OTP_INVALID, ppwszOptionalStatusText);
				break;
			case E_LOCKED:
				SHStrDupW(I18N_ACCOUNT_LOCKED, ppwszOptionalStatusText);
				break;
			default:
				SHStrDupW(L"An error occured.", ppwszOptionalStatusText);
		}
		*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;										
		*pcpsiOptionalStatusIcon = CPSI_ERROR;
		hr = S_FALSE;
		//return S_FALSE;
	}

	goto CleanUpAndReturn; // To avoid C4102
CleanUpAndReturn:
	ZERO(username);
	ZERO(domain);

	_CleanPasswordFields();

    return hr;
}

HRESULT CMultiOneTimePasswordCredential::_CheckOtp(
	__deref_in PWSTR user,
	__deref_in PWSTR otp
	)
{
#ifdef ENABLE_MASTER_LOGON_CODE
	if (wcscmp(_rgFieldStrings[SFI_OTP_PASSWORD_TEXT], CMOTPC_MASTER_LOGON_CODE)==0)
		return S_OK;
#endif

	CMultiOneTimePassword pMOTP;

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("user: "); OutputDebugStringW(user); OutputDebugStringA("\n");	
	OutputDebugStringA("otp: "); OutputDebugStringW(otp); OutputDebugStringA("\n");	
	//*/
#endif

	HRESULT hr = E_FAIL;

	INIT_ZERO_CHAR(c_user, 64);
	INIT_ZERO_CHAR(c_otp, 64);

	__WideCharToChar(user, sizeof(c_user), c_user);
	__WideCharToChar(otp, sizeof(c_otp), c_otp);

	if (c_user[0] && c_otp[0]) {
        hr = pMOTP.OTPCheckPassword(c_user, c_otp);
	}

	goto CleanUpAndReturn; // To avoid C4102
CleanUpAndReturn:
	ZERO(c_user);
	ZERO(c_otp);
	
	return hr;
}

HRESULT CMultiOneTimePasswordCredential::_DoKerberosChangePassword(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__in PWSTR username,
	__in PWSTR password_old,
	__in PWSTR password_new
	)
{
	KERB_CHANGEPASSWORD_REQUEST kcpr;
	ZeroMemory(&kcpr, sizeof(kcpr));

	HRESULT hr;

	WCHAR wsz[64];
    DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = true;

	if (_domain_name && _domain_name[0])
		wcscpy_s(wsz, ARRAYSIZE(wsz), _domain_name);
	else
		bGetCompName = GetComputerNameW(wsz, &cch);

    if ((_domain_name && _domain_name[0]) || bGetCompName)
    {
		hr = UnicodeStringInitWithString(wsz, &kcpr.DomainName);
		if (SUCCEEDED(hr))
		{
			hr = UnicodeStringInitWithString(username, &kcpr.AccountName);
			if (SUCCEEDED(hr))
			{
				hr = UnicodeStringInitWithString(password_old, &kcpr.OldPassword);
				hr = UnicodeStringInitWithString(password_new, &kcpr.NewPassword);
				if (SUCCEEDED(hr))
				{
					kcpr.MessageType = KerbChangePasswordMessage;
					kcpr.Impersonating=FALSE;
					hr = KerbChangePasswordPack( kcpr, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
					if (SUCCEEDED(hr))
					{
						ULONG ulAuthPackage;
						hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
						if (SUCCEEDED(hr))
						{
							pcpcs->ulAuthenticationPackage = ulAuthPackage;
							pcpcs->clsidCredentialProvider = CLSID_CSample;
  
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
						}
					}
				}
			}
		}
	}
	else
	{
		DWORD dwErr = GetLastError();
		hr = HRESULT_FROM_WIN32(dwErr);
	}

	return hr;
}

HRESULT CMultiOneTimePasswordCredential::_DoKerberosLogon(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    __out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__in PWSTR username,
	__in PWSTR password
	)
{
	HRESULT hr;

	WCHAR wsz[64];
    DWORD cch = ARRAYSIZE(wsz);
	BOOL  bGetCompName = true;

	if (_domain_name && _domain_name[0])
		wcscpy_s(wsz, ARRAYSIZE(wsz), _domain_name);
	else
		bGetCompName = GetComputerNameW(wsz, &cch);

    if ((_domain_name && _domain_name[0]) || bGetCompName)
    {
        PWSTR pwzProtectedPassword;

        hr = ProtectIfNecessaryAndCopyPassword(password, _cpus, &pwzProtectedPassword);

        if (SUCCEEDED(hr))
        {
            KERB_INTERACTIVE_UNLOCK_LOGON kiul;

            // Initialize kiul with weak references to our credential.
            hr = KerbInteractiveUnlockLogonInit(wsz, username, pwzProtectedPassword, _cpus, &kiul);

            if (SUCCEEDED(hr))
            {
                // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios.  It contains a
                // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                // as necessary.
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
 
                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the 
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
            }

            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    else
    {
        DWORD dwErr = GetLastError();
        hr = HRESULT_FROM_WIN32(dwErr);
    }

	return hr;
}

void CMultiOneTimePasswordCredential::_SetFieldScenario(
	__in FIELD_SCENARIO scenario
	)
{
	_SetFieldScenario(scenario, NULL, NULL);
}

void CMultiOneTimePasswordCredential::_SetFieldScenario(
	__in FIELD_SCENARIO scenario,
	__in_opt PWSTR large_text,
	__in_opt PWSTR small_text
	)
{
	switch (scenario)
	{
	case SCENARIO_LOGON_BASE:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,		CPFIS_FOCUSED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,			CPFIS_NONE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT,			CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,			CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,			CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,				CPFS_DISPLAY_IN_SELECTED_TILE);	
		break;

	case SCENARIO_CHANGE_PASSWORD:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,		CPFIS_FOCUSED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,			CPFIS_NONE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT,			CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,			CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,			CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,				CPFS_HIDDEN);	
		break;

	case SCENARIO_UNLOCK_BASE:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,		CPFIS_FOCUSED);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,			CPFIS_NONE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT,			CPFS_DISPLAY_IN_BOTH);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,			CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,			CPFS_DISPLAY_IN_SELECTED_TILE);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,				CPFS_DISPLAY_IN_SELECTED_TILE);	
		break;

	case SCENARIO_LOGON_CHALLENGE:
	case SCENARIO_UNLOCK_CHALLENGE:
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_USERNAME,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS,		CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFIS_NONE);
		_pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_OTP_PASS,			CPFIS_NONE);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT,			CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_USERNAME,			CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS,			CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_1,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_LDAP_PASS_NEW_2,	CPFS_HIDDEN);
		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_PASS,				CPFS_HIDDEN);	
		break;

	case SCENARIO_NO_CHANGE:
	default:
		break;
	}

	if (large_text)
		_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LARGE_TEXT, large_text);
	else
	{
		wchar_t text[sizeof(_default_login_text)];

		int size = MultiByteToWideChar(CP_ACP, 0, _default_login_text, -1, text, 0);
		MultiByteToWideChar(CP_ACP, 0, _default_login_text, -1, text, size);

		_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_LARGE_TEXT, text);
	}

	if (small_text)
	{
		_pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_SMALL_TEXT, small_text);

		_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
	}
	else
	{		
		 if (_cpus == CPUS_UNLOCK_WORKSTATION)
			 _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_SMALL_TEXT, WORKSTATION_LOCKED);
		 else
		 {
			 _pCredProvCredentialEvents->SetFieldString(this, SFI_OTP_SMALL_TEXT, L"");

			_pCredProvCredentialEvents->SetFieldState(this, SFI_OTP_SMALL_TEXT, CPFS_HIDDEN);
		 }
	}
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CMultiOneTimePasswordCredential::ReportResult(
    __in NTSTATUS ntsStatus, 
    __in NTSTATUS ntsSubstatus,
    __deref_out_opt PWSTR* ppwszOptionalStatusText, 
    __out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
	//UNREFERENCED_PARAMETER(ntsStatus);
    UNREFERENCED_PARAMETER(ntsSubstatus);
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	_forced_password_change = (ntsStatus == STATUS_PASSWORD_MUST_CHANGE) ? 1 : _forced_password_change;

	return E_NOTIMPL; // The LogonUI should believe we don't implement it to not interfere with default dialogs
}
