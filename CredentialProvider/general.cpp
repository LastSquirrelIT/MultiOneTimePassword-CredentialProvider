#include "general.h"

namespace General
{

	namespace Logon
	{

		HRESULT KerberosLogon(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
			)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr;

			WCHAR wsz[MAX_SIZE_DOMAIN];
			DWORD cch = ARRAYSIZE(wsz);
			BOOL  bGetCompName = false;

			if (domain == NULL || domain[0] == NULL)
				bGetCompName = GetComputerNameW(wsz, &cch);

			if (bGetCompName)
				domain = wsz;

			DebugPrintLn("Credential:");
			DebugPrintLn(username);
			DebugPrintLn(password);
			DebugPrintLn(domain);

			if (domain != NULL || bGetCompName)
			{
				PWSTR pwzProtectedPassword;

				hr = ProtectIfNecessaryAndCopyPassword(password, cpus, &pwzProtectedPassword);

				if (SUCCEEDED(hr))
				{
					KERB_INTERACTIVE_UNLOCK_LOGON kiul;

					// Initialize kiul with weak references to our credential.
					hr = KerbInteractiveUnlockLogonInit(domain, username, pwzProtectedPassword, cpus, &kiul);

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

								// At self point the credential has created the serialized credential used for logon
								// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
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

		HRESULT CredPackAuthentication(
			__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
			__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs,
			__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
			__in PWSTR username,
			__in PWSTR password,
			__in PWSTR domain
			)
		{
			DebugPrintLn(__FUNCTION__);

			PWSTR pwzProtectedPassword;
			HRESULT hr = ProtectIfNecessaryAndCopyPassword(password, cpus, &pwzProtectedPassword);

			if (SUCCEEDED(hr))
			{
				PWSTR domainUsername = NULL;
				hr = DomainUsernameStringAlloc(domain, username, &domainUsername);

				if (SUCCEEDED(hr))
				{
					DWORD size = 0;
					BYTE* rawbits = NULL;

					if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & Data::Provider::Get()->credPackFlags) ? CRED_PACK_WOW_BUFFER : 0, domainUsername, password, rawbits, &size))
					{
						// We received the necessary size, let's allocate some rawbits
						if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
						{
							rawbits = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);

							if (!CredPackAuthenticationBufferW((CREDUIWIN_PACK_32_WOW & Data::Provider::Get()->credPackFlags) ? CRED_PACK_WOW_BUFFER : 0, domainUsername, password, rawbits, &size))
							{
								HeapFree(GetProcessHeap(), 0, rawbits);
								HeapFree(GetProcessHeap(), 0, domainUsername);

								hr = HRESULT_FROM_WIN32(GetLastError());
							}
							else
							{
								pcpcs->rgbSerialization = rawbits;
								pcpcs->cbSerialization = size;
							}
						}
						else
						{
							HeapFree(GetProcessHeap(), 0, domainUsername);
							hr = HRESULT_FROM_WIN32(GetLastError());
						}
					}

					if (SUCCEEDED(hr))
					{
						ULONG ulAuthPackage;
						hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

						if (SUCCEEDED(hr))
						{
							pcpcs->ulAuthenticationPackage = ulAuthPackage;
							pcpcs->clsidCredentialProvider = CLSID_CSample;

							// At self point the credential has created the serialized credential used for logon
							// By setting self to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
							// that we have all the information we need and it should attempt to submit the 
							// serialized credential.
							*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
						}
					}
				}

				CoTaskMemFree(pwzProtectedPassword);
			}

			return hr;
		}

	} // Namespace Logon

	namespace Fields
	{

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
			)
		{
			SetScenario(self, pCPCE, SCENARIO_NO_CHANGE, large_text, small_text);
		}

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario
			)
		{
			SetScenario(self, pCPCE, scenario, NULL, NULL);
		}

		void SetScenario(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in SCENARIO scenario,
			__in_opt PWSTR large_text,
			__in_opt PWSTR small_text
			)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr = S_OK;
			switch (scenario)
			{
			case SCENARIO_LOGON_BASE:
				hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairs);
				break;

			case SCENARIO_UNLOCK_BASE:
				hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsUnlock);
				break;

			case SCENARIO_SECOND_STEP:
				hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsSecondStep);
				break;

			case SCENARIO_CHANGE_PASSWORD:
				hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioChangePasswordFieldStatePairs);
				break;

			case SCENARIO_RESYNC:
				hr = SetFieldStatePairBatch(self, pCPCE, s_rgScenarioLogonUnlockFieldStatePairsResync);
				break;

			case SCENARIO_NO_CHANGE:
			default:
				break;
			}

			// Set text fields separately

			int largeTextFieldId = 0, smallTextFieldId = 0;

			//switch (General::Fields::GetCurrentUsageScenario())
			switch (GetCurrentUsageScenario())
			{
			case CPUS_LOGON:
			case CPUS_UNLOCK_WORKSTATION:
				largeTextFieldId = LUFI_OTP_LARGE_TEXT;
				smallTextFieldId = LUFI_OTP_SMALL_TEXT;
				break;
			case CPUS_CHANGE_PASSWORD:
				largeTextFieldId = CPFI_OTP_LARGE_TEXT;
				smallTextFieldId = CPFI_OTP_SMALL_TEXT;
				break;
			case CPUS_CREDUI:
				largeTextFieldId = CFI_OTP_LARGE_TEXT;
				smallTextFieldId = CFI_OTP_SMALL_TEXT;
				break;
			default:
				break;
			}

			if (large_text)
			{
				DebugPrintLn("Large Text:");
				DebugPrintLn(large_text);
				pCPCE->SetFieldString(self, largeTextFieldId, large_text);
			}

			if (small_text)
			{
				DebugPrintLn("Small Text:");
				DebugPrintLn(small_text);
				pCPCE->SetFieldString(self, smallTextFieldId, small_text);
				//pCPCE->SetFieldState(self, smallTextFieldId, CPFS_DISPLAY_IN_SELECTED_TILE);
			}
			else
			{
				DebugPrintLn("Small Text: Empty");
				pCPCE->SetFieldString(self, smallTextFieldId, L"");
				pCPCE->SetFieldState(self, smallTextFieldId, CPFS_HIDDEN);
			}
		}

		HRESULT SetFieldStatePairBatch(
			__in ICredentialProviderCredential* self,
			__in ICredentialProviderCredentialEvents* pCPCE,
			__in const FIELD_STATE_PAIR* pFSP
			) {
			DebugPrintLn(__FUNCTION__);

			HRESULT hr = S_OK;

			if (!pCPCE || !pFSP)
				return E_INVALIDARG;

			for (unsigned int i = 0; i < GetCurrentNumFields() && SUCCEEDED(hr); i++)
			{
				hr = pCPCE->SetFieldState(self, i, pFSP[i].cpfs);

				if (SUCCEEDED(hr))
					hr = pCPCE->SetFieldInteractiveState(self, i, pFSP[i].cpfis);
			}

			return hr;
		}

		HRESULT Clear(wchar_t* (&field_strings)[MAX_NUM_FIELDS], CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR(&pcpfd)[MAX_NUM_FIELDS], ICredentialProviderCredential* pcpc, ICredentialProviderCredentialEvents* pcpce, char clear)
		{
			DebugPrintLn(__FUNCTION__);

			HRESULT hr = S_OK;

			for (unsigned int i = 0; i < GetCurrentNumFields() && SUCCEEDED(hr); i++)
			{
				char do_something = 0;

				if ((pcpfd[i].cpft == CPFT_PASSWORD_TEXT && clear >= CLEAR_FIELDS_CRYPT) || (pcpfd[i].cpft == CPFT_EDIT_TEXT && clear >= CLEAR_FIELDS_EDIT_AND_CRYPT))
				{
					if (field_strings[i])
					{
						// CoTaskMemFree (below) deals with NULL, but StringCchLength does not.
						size_t len = lstrlen(field_strings[i]);
						SecureZeroMemory(field_strings[i], len * sizeof(*field_strings[i]));

						do_something = 1;
					}
				}

				if (do_something || clear >= CLEAR_FIELDS_ALL)
				{
					CoTaskMemFree(field_strings[i]);
					hr = SHStrDupW(L"", &field_strings[i]);

					if (pcpce)
						pcpce->SetFieldString(pcpc, i, field_strings[i]);

					if (clear == CLEAR_FIELDS_ALL_DESTROY)
						CoTaskMemFree(pcpfd[i].pszLabel);
				}
			}

			return hr;
		}

		unsigned int GetCurrentNumFields()
		{
			DebugPrintLn(__FUNCTION__);

			int numFields = 0;

			if (Data::Provider::Get() != NULL)
			{
				/*
				switch (General::Fields::GetCurrentUsageScenario())
				{
				case CPUS_LOGON:
				case CPUS_UNLOCK_WORKSTATION:
					numFields = LUFI_NUM_FIELDS;
					break;
				case CPUS_CHANGE_PASSWORD:
					numFields = CPFI_NUM_FIELDS;
					break;
				default:
					break;
				}
				*/

				numFields = s_rgCredProvNumFieldsFor[GetCurrentUsageScenario()];
			}

			DebugPrintLn(numFields);

			return numFields;
		}

		unsigned int GetCurrentUsageScenario()
		{
			return Data::Provider::Get()->usage_scenario;
		}

	} // Namespace Fields

} // Namespace General