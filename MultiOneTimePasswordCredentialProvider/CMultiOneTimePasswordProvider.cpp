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

#include <credentialprovider.h>
#include "CMultiOneTimePasswordProvider.h"
#include "CMultiOneTimePasswordCredential.h"
#include "guid.h"

// CMultiOneTimePasswordProvider ////////////////////////////////////////////////////////

CMultiOneTimePasswordProvider::CMultiOneTimePasswordProvider():
    _cRef(1)
{
    DllAddRef();

    ZERO(_rgpCredentials);
	_szUserName = _szDomainName = NULL;
}

CMultiOneTimePasswordProvider::~CMultiOneTimePasswordProvider()
{
	if (_rgpCredentials[0] != NULL)
    {
        _rgpCredentials[0]->Release();
    }

    DllRelease();
}

// Ordinarily we would look at the CPUS and decide whether or not we support this scenario.
// However, in this scenario we're going to create our internal provider and let it answer
// questions like this for us.
HRESULT CMultiOneTimePasswordProvider::SetUsageScenario(
    __in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    __in DWORD dwFlags
    )
{
    UNREFERENCED_PARAMETER(dwFlags);
	HRESULT hr;

	/* DEBUG:
	bool exit = true;
	if (exit)
		return E_NOTIMPL;
	//*/

	static int s_iCredsEnumerated = 0; // 1 = Logon; 2 = Unlock; 3 = Change Password

    //static bool s_bCredsEnumeratedLogon  = false;
	//static bool s_bCredsEnumeratedUnlock = false;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
		if (s_iCredsEnumerated != 1)
        {
			_cpus = cpus;

			//_GetUserAndDomainName();
			hr = this->_EnumerateCredentials();

			s_iCredsEnumerated = 1;
		}
		else
			hr = S_OK;
		break;

	case CPUS_UNLOCK_WORKSTATION:
        if (s_iCredsEnumerated != 2)
        {
			_cpus = cpus;

			_GetUserAndDomainName();
			hr = this->_EnumerateCredentials();    

            s_iCredsEnumerated = 2;
        }
        else
            hr = S_OK;
        break;

	case CPUS_CHANGE_PASSWORD:
        if (s_iCredsEnumerated != 3)
        {
			_cpus = cpus;

			_GetUserAndDomainName();
			hr = this->_EnumerateCredentials();    

            s_iCredsEnumerated = 3;
        }
        else
            hr = S_OK;
        break;

    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// Get user and domain from session information
void CMultiOneTimePasswordProvider::_GetUserAndDomainName()
{
	PWSTR szUserName   = NULL;
	PWSTR szDomainName = NULL;
	DWORD dwLen;

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("szUserName: (BEFORE) \t");   if (_szUserName   != NULL) OutputDebugStringW(_szUserName);   else OutputDebugStringA("NULL"); OutputDebugStringA("\n");	
	OutputDebugStringA("szDomainName: (BEFORE) \t"); if (_szDomainName != NULL) OutputDebugStringW(_szDomainName); else OutputDebugStringA("NULL"); OutputDebugStringA("\n");	
	//*/
#endif

	if ( ! WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
				WTS_CURRENT_SESSION,
				WTSUserName,
				&szUserName,
				&dwLen)) szUserName = NULL;

	if ( ! WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE,
				WTS_CURRENT_SESSION,
				WTSDomainName,
				&szDomainName,
				&dwLen)) szDomainName = NULL;

	_szUserName   = (szUserName   != NULL && szUserName[0]   != NULL) ? StrDupW(szUserName)   : NULL;
	_szDomainName = (szDomainName != NULL && szDomainName[0] != NULL) ? StrDupW(szDomainName) : NULL;

	if (szUserName != NULL)   WTSFreeMemory(szUserName);
	if (szDomainName != NULL) WTSFreeMemory(szDomainName);

#ifdef _DEBUG
	//*************************** DEBUG:
	OutputDebugStringA("_szUserName: \t");   if (_szUserName   != NULL) OutputDebugStringW(_szUserName);   else OutputDebugStringA("NULL"); OutputDebugStringA("\n");	
	OutputDebugStringA("_szDomainName: \t"); if (_szDomainName != NULL) OutputDebugStringW(_szDomainName); else OutputDebugStringA("NULL"); OutputDebugStringA("\n");	
	//*/
#endif
}

// We pass this along to the wrapped provider.
HRESULT CMultiOneTimePasswordProvider::SetSerialization(
    __in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
    UNREFERENCED_PARAMETER(pcpcs);
	return E_NOTIMPL;
}

// Called by LogonUI to give you a callback. We pass this along to the wrapped provider.
HRESULT CMultiOneTimePasswordProvider::Advise(
    __in ICredentialProviderEvents* pcpe,
    __in UINT_PTR upAdviseContext
    )
{
    UNREFERENCED_PARAMETER(pcpe);
    UNREFERENCED_PARAMETER(upAdviseContext);

    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid. 
// We pass this along to the wrapped provider.
HRESULT CMultiOneTimePasswordProvider::UnAdvise()
{
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired 
// using the field descriptors. We pass this along to the wrapped provider and then append
// our own credential count.
HRESULT CMultiOneTimePasswordProvider::GetFieldDescriptorCount(
    __out DWORD* pdwCount
    )
{
    *pdwCount = SFI_NUM_FIELDS;

    return S_OK;
}

// Gets the field descriptor for a particular field. If this descriptor refers to one owned
// by our wrapped provider, we'll pass it along. Otherwise we provide our own.
HRESULT CMultiOneTimePasswordProvider::GetFieldDescriptorAt(
    __in DWORD dwIndex, 
    __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{    
    HRESULT hr;

	/* DEBUG:
	bool exit = true;
	if (exit)
		return E_NOTIMPL;
	//*/

    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    { 
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If 
// more than one provider specifies a default tile the last cred prov used can select
// the default tile. 
// If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call GetSerialization
// on the credential you've specified as the default and will submit that credential
// for authentication without showing any further UI.
// While we're here, we'll create credentials to wrap each of the credentials created by
// our wrapped provider. The key is to make everything transparent to the owner.
HRESULT CMultiOneTimePasswordProvider::GetCredentialCount(
    __out DWORD* pdwCount,
    __out_range(<,*pdwCount) DWORD* pdwDefault,
    __out BOOL* pbAutoLogonWithDefault
    )
{
    HRESULT hr = S_OK;

	/* DEBUG:
	bool exit = true;
	if (exit)
		return E_NOTIMPL;
	//*/
    
    *pdwCount = 1; //_dwNumCreds;
	*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    return hr;
}

// Returns the credential at the index specified by dwIndex. This function is called by 
// logonUI to enumerate the tiles.
HRESULT CMultiOneTimePasswordProvider::GetCredentialAt(
    __in DWORD dwIndex, 
    __deref_out ICredentialProviderCredential** ppcpc
    )
{
    HRESULT hr;

	/* DEBUG:
	bool exit = true;
	if (exit)
		return E_NOTIMPL;
	//*/

    // Validate parameters.
    //if((dwIndex < _dwNumCreds) && ppcpc)
	if((dwIndex == 0) && ppcpc)
    {
        hr = _rgpCredentials[dwIndex]->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }
        
    return hr;
}

// Sets up all the credentials for this provider. Since we always show the same tiles, 
// we just set it up once.
HRESULT CMultiOneTimePasswordProvider::_EnumerateCredentials(
	/*__in_opt PWSTR user_name,
	__in_opt PWSTR domain_name*/
	)
{
	HRESULT hr;

	/* DEBUG:
	bool exit = true;
	if (exit)
		return E_NOTIMPL;
	//*/

    // Allocate memory for the new credential.
    CMultiOneTimePasswordCredential* ppc = new CMultiOneTimePasswordCredential();

	if (ppc)
    {
        // Set the Field State Pair and Field Descriptors for ppc's fields
        // to the defaults (s_rgCredProvFieldDescriptors, and s_rgFieldStatePairs).
		if (_cpus == CPUS_UNLOCK_WORKSTATION)
			hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairsUnlock, /*user_name*/ _szUserName, /*domain_name*/ _szDomainName);
		else if (_cpus == CPUS_CHANGE_PASSWORD)
			hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairsChangePassword, /*user_name*/ _szUserName, /*domain_name*/ _szDomainName);
		else
			hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, /*user_name*/ _szUserName, /*domain_name*/ _szDomainName);
        
        if (SUCCEEDED(hr))
        {
            _rgpCredentials[0] = ppc;
            //_dwNumCreds++;
        }
        else
        {
            // Release the pointer to account for the local reference.
            ppc->Release();
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

	return hr;
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
    HRESULT hr;

    CMultiOneTimePasswordProvider* pProvider = new CMultiOneTimePasswordProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}
