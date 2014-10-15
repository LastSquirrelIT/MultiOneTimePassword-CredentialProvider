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

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include "helpers.h"
#include "dll.h"
#include "resource.h"

class CWrappedCredentialEvents : public ICredentialProviderCredentialEvents
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

    IFACEMETHODIMP QueryInterface(__in REFIID riid, __in void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CWrappedCredentialEvents, ICredentialProviderCredentialEvents), // IID_ICredentialProviderCredentialEvents
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }
    
    // ICredentialProviderCredentialEvents
    IFACEMETHODIMP SetFieldState(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in CREDENTIAL_PROVIDER_FIELD_STATE cpfs);
    IFACEMETHODIMP SetFieldInteractiveState(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis);
    IFACEMETHODIMP SetFieldString(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in PCWSTR psz);
    IFACEMETHODIMP SetFieldCheckbox(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in BOOL bChecked, __in PCWSTR pszLabel);
    IFACEMETHODIMP SetFieldBitmap(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in HBITMAP hbmp);
    IFACEMETHODIMP SetFieldComboBoxSelectedItem(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in DWORD dwSelectedItem);
    IFACEMETHODIMP DeleteFieldComboBoxItem(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in DWORD dwItem);
    IFACEMETHODIMP AppendFieldComboBoxItem(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in PCWSTR pszItem);
    IFACEMETHODIMP SetFieldSubmitButton(__in ICredentialProviderCredential *pcpc, __in DWORD dwFieldID, __in DWORD dwAdjacentTo);
    IFACEMETHODIMP OnCreatingWindow(__out HWND *phwndOwner);

    // Local
    CWrappedCredentialEvents();

    void Initialize(__in ICredentialProviderCredential* pWrapperCredential, __in ICredentialProviderCredentialEvents* pEvents);
    void Uninitialize();

private:
    LONG                                 _cRef;
    ICredentialProviderCredential*       _pWrapperCredential;
    ICredentialProviderCredentialEvents* _pEvents;
};
