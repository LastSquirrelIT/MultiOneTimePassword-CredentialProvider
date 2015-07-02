#ifndef _HOOKS_H
#define _HOOKS_H
#pragma once

#include <Shlwapi.h>

#include "common.h"

#include "general.h"
#include "endpoint.h"

namespace Hook
{
#define HOOK_CRITICAL_FAILURE		((HRESULT)0x8880A001)
#define HOOK_CHECK_CRITICAL(hook, trap) if (hook == HOOK_CRITICAL_FAILURE) { DebugPrintLn("Critical Hook Failure"); goto trap; }

	namespace Serialization
	{
		struct DATA
		{
			// Possibly read-write
			CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr;
			CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs;
			PWSTR* status_text;
			CREDENTIAL_PROVIDER_STATUS_ICON* status_icon;
			ICredentialProviderCredentialEvents* pCredProvCredentialEvents;

			// Read-only
			ICredentialProviderCredential* pCredProvCredential;
			wchar_t** field_strings;
			int num_field_strings;

			/*
			// Default ctor
			DATA(
				CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
				CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
				CREDENTIAL_PROVIDER_STATUS_ICON*& status_icon,
				PWSTR*& status_text,
				ICredentialProviderCredentialEvents*& pCredProvCredentialEvents,
				ICredentialProviderCredential* pCredProvCredential
				)
				: pcpcs(pcpcs),
				pcpgsr(pcpgsr),
				status_icon(status_icon),
				status_text(status_text),
				pCredProvCredentialEvents(pCredProvCredentialEvents),
				pCredProvCredential(pCredProvCredential),
				field_strings(NULL),
				num_field_strings(0)
			{}

		private:
			// because:
			//	DATA a;
			//	DATA b;
			//	a = b; // is impossible
			DATA& operator=(const DATA&); // append " = delete;" for C++11
			*/
		};

		DATA*& Get();
		void Init(
			/*
			CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			PWSTR*& ppwszOptionalStatusText,
			CREDENTIAL_PROVIDER_STATUS_ICON*& pcpsiOptionalStatusIcon,
			ICredentialProviderCredentialEvents*& pCredProvCredentialEvents,
			ICredentialProviderCredential* pCredProvCredential
			*/);
		void Deinit();
		void Default();

		HRESULT Initialization(
			/*
			CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			PWSTR*& ppwszOptionalStatusText,
			CREDENTIAL_PROVIDER_STATUS_ICON*& pcpsiOptionalStatusIcon,
			ICredentialProviderCredentialEvents*& pCredProvCredentialEvents,
			ICredentialProviderCredential* pCredProvCredential
			*/);

		HRESULT EndpointInitialization();
		HRESULT DataInitialization();
		HRESULT EndpointLoadDebugData();
		HRESULT EndpointLoadData();
		HRESULT EndpointCallCancelled();
		HRESULT EndpointCallSuccessfull();
		HRESULT EndpointCallContinue();
		HRESULT EndpointCallFailed();
		HRESULT EndpointDeinitialization();
		HRESULT DataDeinitialization();

		HRESULT ChangePasswordSuccessfull();

		HRESULT BypassKerberos();

		HRESULT KerberosCallSuccessfull();
		HRESULT KerberosCallFailed();

		HRESULT BeforeReturn();
	}

	namespace Connect
	{
		HRESULT ChangePassword();
	}
}

#endif
