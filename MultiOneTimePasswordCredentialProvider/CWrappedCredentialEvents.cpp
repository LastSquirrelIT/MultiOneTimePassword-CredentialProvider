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

#include <unknwn.h>

#include "CWrappedCredentialEvents.h"

HRESULT CWrappedCredentialEvents::SetFieldState(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in CREDENTIAL_PROVIDER_FIELD_STATE cpfs)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldState(_pWrapperCredential, dwFieldID, cpfs);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldInteractiveState(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldInteractiveState(_pWrapperCredential, dwFieldID, cpfis);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldString(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in PCWSTR psz)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldString(_pWrapperCredential, dwFieldID, psz);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldBitmap(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in HBITMAP hbmp)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldBitmap(_pWrapperCredential, dwFieldID, hbmp);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldCheckbox(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in BOOL bChecked, __in PCWSTR pszLabel)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldCheckbox(_pWrapperCredential, dwFieldID, bChecked, pszLabel);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldComboBoxSelectedItem(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in DWORD dwSelectedItem)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldComboBoxSelectedItem(_pWrapperCredential, dwFieldID, dwSelectedItem);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::DeleteFieldComboBoxItem(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in DWORD dwItem)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->DeleteFieldComboBoxItem(_pWrapperCredential, dwFieldID, dwItem);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::AppendFieldComboBoxItem(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in PCWSTR pszItem)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->AppendFieldComboBoxItem(_pWrapperCredential, dwFieldID, pszItem);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::SetFieldSubmitButton(__in ICredentialProviderCredential* pcpc, __in DWORD dwFieldID, __in DWORD dwAdjacentTo)
{
    UNREFERENCED_PARAMETER(pcpc);

    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->SetFieldSubmitButton(_pWrapperCredential, dwFieldID, dwAdjacentTo);
    }

    return hr;
}

HRESULT CWrappedCredentialEvents::OnCreatingWindow(__out HWND* phwndOwner)
{
    HRESULT hr = E_FAIL;

    if (_pWrapperCredential && _pEvents)
    {
        hr = _pEvents->OnCreatingWindow(phwndOwner);
    }

    return hr;
}

CWrappedCredentialEvents::CWrappedCredentialEvents() :
    _cRef(1), _pWrapperCredential(NULL), _pEvents(NULL)
{}

// 
// Save a copy of LogonUI's ICredentialProviderCredentialEvents pointer for doing callbacks
// and the "this" pointer of the wrapper credential to specify events as coming from.
//
// Pointers are saved as weak references (ie, without a reference count) to avoid circular 
// references.  (For instance, The wrapper credential has a reference on the wrapped credential
// and the wrapped credential should take a reference on this object.  If we had a reference
// on the wrapper credential, there would be a cycle.)  The wrapper credential must manage
// the lifetime of our weak references through calls to Initialize and Uninitialize to
// prevent our weak references from becoming invalid.
//
void CWrappedCredentialEvents::Initialize(__in ICredentialProviderCredential* pWrapperCredential, __in ICredentialProviderCredentialEvents* pEvents)
{
    _pWrapperCredential = pWrapperCredential;
    _pEvents = pEvents;
}

//
// Erase our weak references on the wrapper credential and LogonUI's
// ICredentialProviderCredentialEvents pointer.
//
void CWrappedCredentialEvents::Uninitialize()
{
    _pWrapperCredential = NULL;
    _pEvents = NULL;
}
