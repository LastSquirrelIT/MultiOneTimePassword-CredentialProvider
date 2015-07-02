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

#include "CCredential.h"

// CCredential ////////////////////////////////////////////////////////

CCredential::CCredential() :
	_cRef(1),
	_pCredProvCredentialEvents(NULL)
{
	DllAddRef();

	_dwComboIndex = 0;

	ZERO(_rgCredProvFieldDescriptors);
	ZERO(_rgFieldStatePairs);
	ZERO(_rgFieldStrings);

	// Initialize config
	Configuration::Init();
	Configuration::Read();

	// END

	Data::General::Init();
	Data::Credential::Init();
	EndpointObserver::Init();
}

CCredential::~CCredential()
{
	General::Fields::Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, NULL, CLEAR_FIELDS_ALL_DESTROY);

	// END
	// Make sure runtime is clean (see ctor "Initialize config variables")
	// Use SecureZeroMemory for confidential information
	Configuration::Deinit();

	// END
	// Endpoint deinit


	// END

	EndpointObserver::Deinint();
	Data::Credential::Deinit();
	Data::General::Deinit();

	DllRelease();
}

HRESULT CCredential::_InitializeField(const FIELD_INITIALIZOR initializor, DWORD field_index)
{
	HRESULT hr = E_INVALIDARG;

	switch (initializor.type)
	{
	case FIT_VALUE:
		DebugPrintLn("...FIT_VALUE");
		hr = SHStrDupW(initializor.value, &_rgFieldStrings[field_index]);
		break;
	case FIT_USERNAME:
		DebugPrintLn("...FIT_USERNAME");
		if (NOT_EMPTY(Data::Credential::Get()->user_name))
			hr = SHStrDupW(Data::Credential::Get()->user_name, &_rgFieldStrings[field_index]);
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[field_index]);
		break;
	case FIT_LOGIN_TEXT:
		DebugPrintLn("...FIT_LOGIN_TEXT");
		wchar_t value[sizeof(Configuration::Get()->login_text)];
		Helper::CharToWideChar(Configuration::Get()->login_text, sizeof(Configuration::Get()->login_text), value);
		hr = SHStrDupW(value, &_rgFieldStrings[field_index]);
		break;
	case FIT_VALUE_OR_LOGIN_TEXT:
		DebugPrintLn("...FIT_VALUE_OR_LOGIN_TEXT");
		if (NOT_EMPTY(Configuration::Get()->login_text))
		{
			DebugPrintLn("......Configuration::Get()->login_text");
			wchar_t value[sizeof(Configuration::Get()->login_text)];
			Helper::CharToWideChar(Configuration::Get()->login_text, sizeof(Configuration::Get()->login_text), value);
			hr = SHStrDupW(value, &_rgFieldStrings[field_index]);
		}
		else
			hr = SHStrDupW(initializor.value, &_rgFieldStrings[field_index]);
		break;
	case FIT_VALUE_OR_LOCKED_TEXT:
		DebugPrintLn("...FIT_VALUE_OR_LOCKED_TEXT");
		if (General::Fields::GetCurrentUsageScenario() == CPUS_UNLOCK_WORKSTATION && NOT_EMPTY(WORKSTATION_LOCKED))
		{
			DebugPrintLn("......General::Fields::GetCurrentUsageScenario() == CPUS_UNLOCK_WORKSTATION");
			hr = SHStrDupW(WORKSTATION_LOCKED, &_rgFieldStrings[field_index]);
		}
		else
			hr = SHStrDupW(value, &_rgFieldStrings[field_index]);
		break;
	case FIT_NONE:
		DebugPrintLn("...FIT_NONE");
		break;
	default:
		hr = SHStrDupW(L"", &_rgFieldStrings[field_index]);
		break;
	}

	return hr;
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
// Optionally takes a password for the SetSerialization case.
HRESULT CCredential::Initialize(
	//__in CProvider* pProvider,
	//__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
	__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
	__in const FIELD_STATE_PAIR* rgfsp,
	__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name,
	__in_opt PWSTR password
	)
{
	DebugPrintLn(__FUNCTION__);

	DebugPrintLn("Username from provider:");
	DebugPrintLn(user_name);
	DebugPrintLn("Domain from provider:");
	DebugPrintLn(domain_name);
	DebugPrintLn("Password from provider:");
	DebugPrintLn(password);

	HRESULT hr = S_OK;

	//Data::Provider::Get()->pProvider = pProvider;
	//General::Fields::GetCurrentUsageScenario() = cpus;

	if (NOT_EMPTY(user_name))
	{
		DebugPrintLn("Copying user_name to credential");
		Data::Credential::Get()->user_name = _wcsdup(user_name);
	}

	if (NOT_EMPTY(domain_name))
	{
		DebugPrintLn("Copying domain_name to credential");
		Data::Credential::Get()->domain_name = _wcsdup(domain_name);
	}
	
	if (NOT_EMPTY(password))
	{
		DebugPrintLn("Copying password to credential");
		Data::Credential::Get()->password = _wcsdup(password);
	}


	// Copy the field descriptors for each field. This is useful if you want to vary the 
	// field descriptors based on what Usage scenario the credential was created for.
	// Initialize the fields	

	// !!!!!!!!!!!!!!!!!!!!
	// !!!!!!!!!!!!!!!!!!!!
	// TODO: make _rgCredProvFieldDescriptors dynamically allocated depending on current CPUS
	// !!!!!!!!!!!!!!!!!!!!
	// !!!!!!!!!!!!!!!!!!!!

	//_rgCredProvFieldDescriptors = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)malloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR) * General::Fields::GetCurrentNumFields());

	//for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
	for (DWORD i = 0; SUCCEEDED(hr) && i < General::Fields::GetCurrentNumFields(); i++)
	{
		DebugPrintLn("Copy field #:");
		DebugPrintLn(i+1);

		_rgFieldStatePairs[i] = rgfsp[i];
		hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);

		if (FAILED(hr))
			break;
		
		if (s_rgCredProvFieldInitializorsFor[General::Fields::GetCurrentUsageScenario()] != NULL)
			_InitializeField(s_rgCredProvFieldInitializorsFor[General::Fields::GetCurrentUsageScenario()][i], i);

		/*
		if (General::Fields::GetCurrentUsageScenario() == CPUS_CHANGE_PASSWORD)
		{
			DebugPrintLn("...CPUS_CHANGE_PASSWORD");
			_InitializeField(s_rgChangePasswordFieldInitializors[i], i);
		}
		else
		{
			DebugPrintLn("...ELSE");
			_InitializeField(s_rgLogonUnlockFieldInitializors[i], i);
		}
		*/
	}

	// Initialize the String values of all the fields.
	/**
	if (SUCCEEDED(hr))
	{
		wchar_t large_text[sizeof(Configuration::Get()->login_text)];
		Helper::CharToWideChar(Configuration::Get()->login_text, sizeof(Configuration::Get()->login_text), large_text);

		hr = SHStrDupW(large_text, &_rgFieldStrings[LUFI_OTP_LARGE_TEXT]);
	}
	if (SUCCEEDED(hr))
	{
		if (General::Fields::GetCurrentUsageScenario() == CPUS_UNLOCK_WORKSTATION)
			hr = SHStrDupW(WORKSTATION_LOCKED, &_rgFieldStrings[LUFI_OTP_SMALL_TEXT]);
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[LUFI_OTP_SMALL_TEXT]);
	}
	if (SUCCEEDED(hr))
	{
		if (General::Fields::GetCurrentUsageScenario() == CPUS_UNLOCK_WORKSTATION && Data::Credential::Get()->user_name)
		{
			hr = SHStrDupW(Data::Credential::Get()->user_name, &_rgFieldStrings[LUFI_OTP_USERNAME]);
		}
		else
			hr = SHStrDupW(L"", &_rgFieldStrings[LUFI_OTP_USERNAME]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[LUFI_OTP_LDAP_PASS]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"", &_rgFieldStrings[LUFI_OTP_PASS]);
	}
	if (SUCCEEDED(hr))
	{
		hr = SHStrDupW(L"Submit", &_rgFieldStrings[LUFI_OTP_SUBMIT_BUTTON]);
	}
	//*/

	DebugPrintLn("Init result:");
	if (SUCCEEDED(hr))
		DebugPrintLn("OK");
	else
		DebugPrintLn("FAIL");

	return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CCredential::Advise(
	__in ICredentialProviderCredentialEvents* pcpce
	)
{
	DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents != NULL)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = pcpce;
	_pCredProvCredentialEvents->AddRef();

	/////

	if (Data::General::Get()->startEndpointObserver == true)
	{
		Data::General::Get()->startEndpointObserver = false;

		if (EndpointObserver::Thread::GetStatus() == EndpointObserver::Thread::STATUS::NOT_RUNNING)
			EndpointObserver::Thread::Create(NULL);
	}

	return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CCredential::UnAdvise()
{
	DebugPrintLn(__FUNCTION__);

	if (_pCredProvCredentialEvents)
	{
		_pCredProvCredentialEvents->Release();
	}
	_pCredProvCredentialEvents = NULL;
	return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the 
// field definitions.  But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CCredential::SetSelected(__out BOOL* pbAutoLogon)
{
	DebugPrintLn(__FUNCTION__);

	*pbAutoLogon = FALSE;

	HRESULT hr = S_OK;

	HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointInitialization(), CleanUpAndReturn);

	if (EndpointObserver::Thread::GetStatus() == EndpointObserver::Thread::STATUS::FINISHED)
	{
		DebugPrintLn("Observer FINISHED");

		if (EndpointObserver::Result()->returnValue == EPT_SUCCESS)
		{
			DebugPrintLn("EPT_SUCCESS");

			EndpointObserver::Result()->returnValue = EPT_UNKNOWN;
			Data::General::Get()->bypassEndpoint = true;
			Data::General::Get()->bypassDataInitialization = true;
			//Data::General::Get()->bypassDataDeinitialization = true;

			*pbAutoLogon = true;
		}
		else
		{
			DebugPrintLn("EPT_FAILURE or EPT_UNKNOWN");

			Endpoint::Get()->protectMe = false;
			Hook::Serialization::EndpointDeinitialization();

			hr = E_FAIL;
		}

		EndpointObserver::Thread::Destroy();
	}

CleanUpAndReturn:
	Hook::Serialization::EndpointDeinitialization();
	return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CCredential::SetDeselected()
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr = S_OK;

	/////////
	HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointInitialization(), DeinitEndpoint);
	Endpoint::Get()->protectMe = false;
DeinitEndpoint:
	Hook::Serialization::EndpointDeinitialization();

	EndpointObserver::Thread::Shutdown();
	/////////

	General::Fields::Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_EDIT_AND_CRYPT);
	
	if (General::Fields::GetCurrentUsageScenario() == CPUS_UNLOCK_WORKSTATION)
	{
		General::Fields::SetScenario(this, _pCredProvCredentialEvents, General::Fields::SCENARIO_UNLOCK_BASE, NULL, WORKSTATION_LOCKED);
	}
	else
	{
		General::Fields::SetScenario(this, _pCredProvCredentialEvents, General::Fields::SCENARIO_LOGON_BASE);
	}

	return hr;
}

// Gets info for a particular field of a tile. Called by logonUI to get information to 
// display the tile.
HRESULT CCredential::GetFieldState(
	__in DWORD dwFieldID,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
	)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr;

	// Validate paramters.
	if ((dwFieldID < General::Fields::GetCurrentNumFields()) && pcpfs && pcpfis)
	{
		*pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
		*pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;

		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CCredential::GetStringValue(
	__in DWORD dwFieldID,
	__deref_out PWSTR* ppwsz
	)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr;

	// Check to make sure dwFieldID is a legitimate index.
	if (dwFieldID < General::Fields::GetCurrentNumFields() && ppwsz)
	{
		// Make a copy of the string and return that. The caller
		// is responsible for freeing it.
		hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

// Gets the image to show in the user tile.
HRESULT CCredential::GetBitmapValue(
	__in DWORD dwFieldID,
	__out HBITMAP* phbmp
	)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr;
	if ((LUFI_OTP_LOGO == dwFieldID) && phbmp)
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

	DebugPrintLn(hr);

	return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be 
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CCredential::GetSubmitButtonValue(
	__in DWORD dwFieldID,
	__out DWORD* pdwAdjacentTo
	)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr;

	// Validate parameters.

	// !!!!!!!!!!!!!
	// !!!!!!!!!!!!!
	// TODO: Change scenario data structures to determine correct submit-button and pdwAdjacentTo dynamically

	if (LUFI_OTP_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		// pdwAdjacentTo is a pointer to the fieldID you want the submit button to appear next to.
		*pdwAdjacentTo = LUFI_OTP_PASS;
		hr = S_OK;
	}
	else if (CPFI_OTP_SUBMIT_BUTTON == dwFieldID && pdwAdjacentTo)
	{
		*pdwAdjacentTo = CPFI_OTP_PASS_NEW_2;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field.
HRESULT CCredential::SetStringValue(
	__in DWORD dwFieldID,
	__in PCWSTR pwz
	)
{
	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < General::Fields::GetCurrentNumFields() &&
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

	DebugPrintLn(hr);

	return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the 
// currently selected item (pdwSelectedItem).
HRESULT CCredential::GetComboBoxValueCount(
	__in DWORD dwFieldID,
	__out DWORD* pcItems,
	__out_range(< , *pcItems) DWORD* pdwSelectedItem
	)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < General::Fields::GetCurrentNumFields() &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		*pcItems = 0; // ARRAYSIZE(s_rgLogonUnlockComboBoxModeStrings);
		*pdwSelectedItem = 0;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return S_OK;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CCredential::GetComboBoxValueAt(
	__in DWORD dwFieldID,
	__in DWORD dwItem,
	__deref_out PWSTR* ppwszItem
	)
{
	DebugPrintLn(__FUNCTION__);
	UNREFERENCED_PARAMETER(ppwszItem);
	UNREFERENCED_PARAMETER(dwItem);

	HRESULT hr;

	// Validate parameters.
	if (dwFieldID < General::Fields::GetCurrentNumFields() &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		hr = E_INVALIDARG; //SHStrDupW(s_rgLogonUnlockComboBoxModeStrings[dwItem], ppwszItem);
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CCredential::SetComboBoxSelectedValue(
	__in DWORD dwFieldID,
	__in DWORD dwSelectedItem
	)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr = 0;

	// Validate parameters.
	if (dwFieldID < General::Fields::GetCurrentNumFields() &&
		(CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		_dwComboIndex = dwSelectedItem;
		hr = S_OK;
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

HRESULT CCredential::CommandLinkClicked(__in DWORD dwFieldID)
{
	DebugPrintLn(__FUNCTION__);

	HRESULT hr = E_FAIL;

	// Validate parameter.
	if (dwFieldID < General::Fields::GetCurrentNumFields() &&
		(CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
	{
		General::Fields::SetScenario(this, _pCredProvCredentialEvents, General::Fields::SCENARIO_RESYNC, NULL, L"Please enter two OTPs to synchronize them");
	}
	else
	{
		hr = E_INVALIDARG;
	}

	DebugPrintLn(hr);

	return hr;
}

//------------- 
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CCredential::GetCheckboxValue(
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

HRESULT CCredential::SetCheckboxValue(
	__in DWORD dwFieldID,
	__in BOOL bChecked
	)
{
	UNREFERENCED_PARAMETER(dwFieldID);
	UNREFERENCED_PARAMETER(bChecked);

	return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//

// Collect the username and password into a serialized credential for the correct usage scenario 
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials 
// back to the system to log on.
HRESULT CCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	DebugPrintLn(__FUNCTION__);

	//////
	//General::Fields::SetScenario(this, _pCredProvCredentialEvents, General::Fields::SCENARIO_UNLOCK_OTP);
	//Sleep(5000);
	//////

	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;

	HRESULT hr = E_FAIL, retVal = S_OK;

	// Logon cancelled
	if (Data::Credential::Get()->userCanceled)
	{
		Hook::Serialization::EndpointCallCancelled();

		retVal = S_FALSE;
		goto CleanUpAndReturn;
	}

	// reference parameters to internal datastructures (we need them in the hooks)
	HOOK_CHECK_CRITICAL(Hook::Serialization::Initialization(), CleanUpAndReturn);

	Hook::Serialization::Get()->pCredProvCredentialEvents = _pCredProvCredentialEvents;
	Hook::Serialization::Get()->pCredProvCredential = this;

	Hook::Serialization::Get()->pcpcs = pcpcs;
	Hook::Serialization::Get()->pcpgsr = pcpgsr;

	Hook::Serialization::Get()->status_icon = pcpsiOptionalStatusIcon;
	Hook::Serialization::Get()->status_text = ppwszOptionalStatusText;

	Hook::Serialization::Get()->field_strings = _rgFieldStrings;
	Hook::Serialization::Get()->num_field_strings = General::Fields::GetCurrentNumFields();
	/////

	if (Data::Credential::Get()->endpointStatus == E_NOT_SET)
	{
		HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointInitialization(), CleanUpAndReturn);
		HOOK_CHECK_CRITICAL(Hook::Serialization::DataInitialization(), CleanUpAndReturn);

		HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointLoadData(), CleanUpAndReturn);
		HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointLoadDebugData(), CleanUpAndReturn);
	}

	/* We currently won't support CPUS_CREDUI, but we are well prepared */
	// Connect() is not called for CPUS_CREDUI, so we need to call the endpoint here
	
	if (General::Fields::GetCurrentUsageScenario() == CPUS_CREDUI)
	{
		if (Data::General::Get()->bypassEndpoint == false)
			Data::Credential::Get()->endpointStatus = Endpoint::Call();
	}
	//*/

	/*
	// Logon cancelled
	if (Data::Credential::Get()->userCanceled)
	{
		Hook::Serialization::EndpointCallCancelled();

		retVal = S_FALSE;
		goto CleanUpAndReturn;
	}
	*/

	// Password changed
	if (General::Fields::GetCurrentUsageScenario() == CPUS_CHANGE_PASSWORD)
	{
		Hook::Serialization::ChangePasswordSuccessfull();

		retVal = S_FALSE;
		goto CleanUpAndReturn;
	}

	if (Data::General::Get()->bypassKerberos == true)
	{
		Data::General::Get()->bypassKerberos = false;

		HOOK_CHECK_CRITICAL(Hook::Serialization::BypassKerberos(), CleanUpAndReturn);

		goto CleanUpAndReturn; // because we dont want to hit the pcpgsr selection switch below
	}
	else if (SUCCEEDED(Data::Credential::Get()->endpointStatus) || Data::General::Get()->bypassEndpoint == true)
	{
		HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointCallSuccessfull(), CleanUpAndReturn);

		if (Data::Provider::Get()->usage_scenario == CPUS_CREDUI)
			hr = General::Logon::CredPackAuthentication(pcpgsr, pcpcs, Data::Provider::Get()->usage_scenario, Data::Gui::Get()->user_name, Data::Gui::Get()->ldap_pass, Data::Gui::Get()->domain_name);
		else
			hr = General::Logon::KerberosLogon(pcpgsr, pcpcs, Data::Provider::Get()->usage_scenario, Data::Gui::Get()->user_name, Data::Gui::Get()->ldap_pass, Data::Gui::Get()->domain_name);

		if (SUCCEEDED(hr))
		{
			HOOK_CHECK_CRITICAL(Hook::Serialization::KerberosCallSuccessfull(), CleanUpAndReturn);
		}
		else
		{
			HOOK_CHECK_CRITICAL(Hook::Serialization::KerberosCallFailed(), CleanUpAndReturn);
			retVal = S_FALSE;
		}

		goto CleanUpAndReturn; // because we dont want to hit the pcpgsr selection switch below
	}
	else if (Data::Credential::Get()->endpointStatus == ENDPOINT_AUTH_CONTINUE)
	{
		HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointCallContinue(), CleanUpAndReturn);
	}
	else
	{
		HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointCallFailed(), CleanUpAndReturn);
		retVal = S_FALSE;
	}

	switch (Endpoint::GetStatus())
	{
	case Endpoint::FINISHED:
		*pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		break;
	case Endpoint::NOT_FINISHED:
	default:
		*pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
	}

	goto CleanUpAndReturn;
CleanUpAndReturn:
	Hook::Serialization::DataDeinitialization();
	Hook::Serialization::EndpointDeinitialization();

	if (Data::General::Get()->clearFields)
		General::Fields::Clear(_rgFieldStrings, _rgCredProvFieldDescriptors, this, _pCredProvCredentialEvents, CLEAR_FIELDS_CRYPT);
	else
		Data::General::Get()->clearFields = true; // it's a one-timer...

	Hook::Serialization::BeforeReturn();

	return retVal;
}

HRESULT CCredential::Connect(__in IQueryContinueWithStatus *pqcws)
{
	DebugPrintLn(__FUNCTION__);

	//Data::Credential::Default();
	Data::Credential::Get()->pqcws = pqcws;

	/////
	HOOK_CHECK_CRITICAL(Hook::Serialization::Initialization(), Exit);

	Hook::Serialization::Get()->pCredProvCredential = this;
	Hook::Serialization::Get()->pCredProvCredentialEvents = _pCredProvCredentialEvents;
	Hook::Serialization::Get()->field_strings = _rgFieldStrings;
	Hook::Serialization::Get()->num_field_strings = General::Fields::GetCurrentNumFields();
	/////

	HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointInitialization(), Exit);
	HOOK_CHECK_CRITICAL(Hook::Serialization::DataInitialization(), Exit);

	HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointLoadData(), Exit);
	HOOK_CHECK_CRITICAL(Hook::Serialization::EndpointLoadDebugData(), Exit);

	if (General::Fields::GetCurrentUsageScenario() == CPUS_UNLOCK_WORKSTATION || General::Fields::GetCurrentUsageScenario() == CPUS_LOGON)
	{
		if (Data::General::Get()->bypassEndpoint == false)
			Data::Credential::Get()->endpointStatus = Endpoint::Call();
	}
	else if (General::Fields::GetCurrentUsageScenario() == CPUS_CHANGE_PASSWORD)
	{
		// TODO: May be critical?
		Hook::Connect::ChangePassword();
	}

	// Did the user click the "Cancel" button?
	if (pqcws->QueryContinue() != S_OK)
	{
		DebugPrintLn("User cancelled");
		Data::Credential::Get()->userCanceled = true;
	}

Exit:
	Data::Credential::Get()->pqcws = NULL;

	return S_OK; // always S_OK
}

HRESULT CCredential::Disconnect()
{
	return E_NOTIMPL;
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to 
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CCredential::ReportResult(
	__in NTSTATUS ntsStatus,
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText,
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	DebugPrintLn(__FUNCTION__);

	UNREFERENCED_PARAMETER(ntsStatus);
	UNREFERENCED_PARAMETER(ntsSubstatus);
	UNREFERENCED_PARAMETER(ppwszOptionalStatusText);
	UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

	return E_NOTIMPL;
}
