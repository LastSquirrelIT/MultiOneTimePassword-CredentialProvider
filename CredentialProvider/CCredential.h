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

#ifndef _CCREDENTIAL_H
#define _CCREDENTIAL_H

#include <unknwn.h>
#include <helpers.h>

//#include "CProvider.h"

//#include "dependencies.h"

#include "Dll.h"
#include "common.h"

#include "config.h"
#include "hooks.h"
#include "general.h"
#include "data.h"
#include "helper.h"

#include "endpoint.h"
#include "EndpointObserver.h"

//#define OOTP_CHALLENGE	((HRESULT)0x88809001)
//#define OOTP_FAILURE	((HRESULT)0x88809002)
//#define OOTP_SUCCESS	((HRESULT)0x88809101)

#define TIMEOUT_TEXT L"Timeout: %i secs."
#define WORKSTATION_LOCKED Data::Credential::Get()->user_name

class CCredential : public IConnectableCredentialProviderCredential
{
public:
	// IUnknown
	IFACEMETHODIMP_(ULONG) AddRef()
	{
		return ++_cRef;
	}

	IFACEMETHODIMP_(ULONG) Release()
	{
		LONG cRef = --_cRef;
		if (!cRef)
		{
			delete this;
		}
		return cRef;
	}

	IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void** ppv)
	{
		static const QITAB qitOnlyCredUI[] =
		{
			QITABENT(CCredential, ICredentialProviderCredential),
			{ 0 },
		};

		static const QITAB qitFull[] =
		{
			QITABENT(CCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
			QITABENT(CCredential, IConnectableCredentialProviderCredential), // IID_IConnectableCredentialProviderCredential
			{ 0 },
		};

		//if (General::Fields::GetCurrentUsageScenario() == CPUS_CREDUI)
		if (General::Fields::GetCurrentUsageScenario() == CPUS_CREDUI)
		{
			// being prepared is good
			return QISearch(this, qitOnlyCredUI, riid, ppv);
		}
		else
		{
			return QISearch(this, qitFull, riid, ppv);
		}
	}
public:
	// ICredentialProviderCredential
	IFACEMETHODIMP Advise(__in ICredentialProviderCredentialEvents* pcpce);
	IFACEMETHODIMP UnAdvise();

	IFACEMETHODIMP SetSelected(__out BOOL* pbAutoLogon);
	IFACEMETHODIMP SetDeselected();

	IFACEMETHODIMP GetFieldState(__in DWORD dwFieldID,
		__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
		__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

	IFACEMETHODIMP GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz);
	IFACEMETHODIMP GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp);
	IFACEMETHODIMP GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel);
	IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems, __out_range(< , *pcItems) DWORD* pdwSelectedItem);
	IFACEMETHODIMP GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem, __deref_out PWSTR* ppwszItem);
	IFACEMETHODIMP GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo);

	IFACEMETHODIMP SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz);
	IFACEMETHODIMP SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked);
	IFACEMETHODIMP SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem);
	IFACEMETHODIMP CommandLinkClicked(__in DWORD dwFieldID);

	IFACEMETHODIMP GetSerialization(__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
		__deref_out_opt PWSTR* ppwszOptionalStatusText,
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
	IFACEMETHODIMP ReportResult(__in NTSTATUS ntsStatus,
		__in NTSTATUS ntsSubstatus,
		__deref_out_opt PWSTR* ppwszOptionalStatusText,
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

	// IConnectableCredentialProviderCredential 
public:
	IFACEMETHODIMP Connect(__in IQueryContinueWithStatus *pqcws);
	IFACEMETHODIMP Disconnect();

	// Default
	CCredential();

	virtual ~CCredential();

	///////////////////////////////////

public:
	HRESULT Initialize(//__in CProvider* pProvider,
		//__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
		__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
		__in const FIELD_STATE_PAIR* rgfsp,
		__in_opt PWSTR user_name,
		__in_opt PWSTR domain_name,
		__in_opt PWSTR password);

	///////////////////////////////////

private: ////////////// FUNCS
	// Endpoint funcs

	// END
	HRESULT _InitializeField(const FIELD_INITIALIZOR initializor, DWORD field_index);

private: ////////////// VARS
	// Default vars
	LONG									_cRef;

	//CREDENTIAL_PROVIDER_USAGE_SCENARIO		_cpus; // The usage scenario for which we were enumerated.

	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR	_rgCredProvFieldDescriptors[MAX_NUM_FIELDS];	// An array holding the type and 
	//CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*	_rgCredProvFieldDescriptors;					// An array holding the type and 
																							// name of each field in the tile.

	FIELD_STATE_PAIR						_rgFieldStatePairs[MAX_NUM_FIELDS];          // An array holding the state of 
	// each field in the tile.

	wchar_t*								_rgFieldStrings[MAX_NUM_FIELDS];             // An array holding the string 
	// value of each field. This is 
	// different from the name of 
	// the field held in 
	// _rgCredProvFieldDescriptors.
	ICredentialProviderCredentialEvents*	_pCredProvCredentialEvents;

	DWORD                                   _dwComboIndex;                               // Tracks the current index 
	// of our combobox.

	// END
	// General vars
	//PWSTR									_user_name;
	//PWSTR									_domain_name;

	// END
};

#endif
