#ifndef _GENERAL_H
#define _GENERAL_H
#pragma once

#include <helpers.h>
#include <wincred.h>

#include "common.h"
#include "data.h"

namespace General
{
#define MAX_SIZE_DOMAIN 64

	namespace Logon
	{
		HRESULT KerberosLogon(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
			);

		HRESULT CredPackAuthentication(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
			);
	}

	namespace Fields
	{
		enum SCENARIO
		{
			SCENARIO_NO_CHANGE = 0,
			SCENARIO_LOGON_BASE = 1,
			SCENARIO_UNLOCK_BASE = 2,
			SCENARIO_SECOND_STEP = 4,
			SCENARIO_CHANGE_PASSWORD = 5,
			SCENARIO_RESYNC = 6,
		};

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
			);

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario
			);

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
			);

#define CLEAR_FIELDS_CRYPT 0
#define CLEAR_FIELDS_EDIT_AND_CRYPT 1
#define CLEAR_FIELDS_ALL 2
#define CLEAR_FIELDS_ALL_DESTROY 3

		HRESULT Clear(
			wchar_t* (&field_strings)[MAX_NUM_FIELDS],
			CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[MAX_NUM_FIELDS],
			ICredentialProviderCredential* pcpc,
			ICredentialProviderCredentialEvents* pcpce,
			char clear);

		HRESULT SetFieldStatePairBatch(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in const FIELD_STATE_PAIR* pFSP
			);

		unsigned int GetCurrentNumFields();
		unsigned int GetCurrentUsageScenario();
	}
}

#endif
