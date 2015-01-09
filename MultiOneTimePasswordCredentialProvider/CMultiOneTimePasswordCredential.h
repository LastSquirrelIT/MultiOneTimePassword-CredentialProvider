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

#pragma once

#include <helpers.h>
#include "common.h"
#include "dll.h"
#include "resource.h"
#include "CWrappedCredentialEvents.h"

#include "CMultiOneTimePassword.h"

#include "conversions.h"
#include "registry.h"

// BE CAREFULL WHEN ENABLING THE MASTER LOGON CODE. SECURITY RISK!!!
// DO NEVER ENABLE MASTER CODE WHEN IN RELEASE
//#define ENABLE_MASTER_LOGON_CODE

#ifdef ENABLE_MASTER_LOGON_CODE
#ifdef DEBUG
#define CMOTPC_MASTER_LOGON_CODE L"AF8932FFDB"
#endif
#endif

#define DEFAULT_LOGIN_TEXT	"MultiOTP Logon"
#define WORKSTATION_LOCKED	_user_name
#define CHANGE_PASSWORD		L"Change password"

enum FIELD_SCENARIO
{
	SCENARIO_NO_CHANGE			= 0,
	SCENARIO_LOGON_BASE			= 1,
	SCENARIO_UNLOCK_BASE		= 2,
	SCENARIO_LOGON_CHALLENGE	= 3,	
	SCENARIO_UNLOCK_CHALLENGE	= 4,
	SCENARIO_CHANGE_PASSWORD	= 5,
};

class CMultiOneTimePasswordCredential : public ICredentialProviderCredential
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
        static const QITAB qit[] =
        {
            QITABENT(CMultiOneTimePasswordCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            {0},
        };
        return QISearch(this, qit, riid, ppv);
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
    IFACEMETHODIMP GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems, __out_range(<,*pcItems) DWORD* pdwSelectedItem);
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

  public:
    HRESULT Initialize(
				__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, 
				__in const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
				__in const FIELD_STATE_PAIR* rgfsp,
				__in_opt PWSTR user_name,
				__in_opt PWSTR domain_name
			);
    CMultiOneTimePasswordCredential();

    virtual ~CMultiOneTimePasswordCredential();

  private:
	HRESULT								  CMultiOneTimePasswordCredential::_DoKerberosLogon(
											__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
											__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
											__in PWSTR username,
											__in PWSTR password
										  );
	HRESULT								  _CheckOtp(
											__deref_in PWSTR user,
											__deref_in PWSTR otp
										  );
	void								  CMultiOneTimePasswordCredential::_SeparateUserAndDomainName(
											__in wchar_t *domain_slash_username,
											__out wchar_t *username,
											__in int sizeUsername,
											__out_opt wchar_t *domain,
											__in_opt int sizeDomain
										  );
	void								  CMultiOneTimePasswordCredential::_SetFieldScenario(
											__in FIELD_SCENARIO scenario,
											__in_opt PWSTR large_text,
											__in_opt PWSTR small_text
										  );
	void								  CMultiOneTimePasswordCredential::_SetFieldScenario(
											__in FIELD_SCENARIO scenario
										  );
	HRESULT								  CMultiOneTimePasswordCredential::_DoKerberosChangePassword(
											__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
											__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
											__in PWSTR username,
											__in PWSTR password_old,
											__in PWSTR password_new
										  );
	void								  CMultiOneTimePasswordCredential::_CleanPasswordFields();

  private:
    LONG                                  _cRef;
	CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR  _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];  // An array holding the type 
                                                                                        // and name of each field in 
                                                                                        // the tile.

    FIELD_STATE_PAIR                      _rgFieldStatePairs[SFI_NUM_FIELDS];           // An array holding the state 
                                                                                        // of each field in the tile.

    PWSTR                                 _rgFieldStrings[SFI_NUM_FIELDS];              // An array holding the string 
                                                                                        // value of each field. This is 
                                                                                        // different from the name of 
                                                                                        // the field held in 
                                                                                        // _rgCredProvFieldDescriptors.
    
    ICredentialProviderCredentialEvents *_pCredProvCredentialEvents;                    // Used to let our parent know
                                                                                        // when the credentials have
                                                                                        // changed.

    DWORD                                _dwDatabaseIndex;                              // The current selected item
                                                                                        // in our combobox.
	PWSTR								 _user_name;
	PWSTR								 _domain_name;
	char								 _default_login_text[64];

	int									 _forced_password_change; // 0 = no forced change; 1 = forced change; 2 = ready for auto logon; 3 = forced change done
	PWSTR								 _password_buffer;

	char								 _default_domain[256];
};
