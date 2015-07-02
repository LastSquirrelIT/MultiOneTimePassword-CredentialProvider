#include "hooks.h"

namespace Hook
{

namespace Serialization
{

DATA*& Get()
{
	static struct DATA *data = NULL;

	return data;
}

void Default()
{
	struct DATA*& data = Get();

	if (data == NULL)
		return;

	data->pcpcs = NULL;
	data->pcpgsr = NULL;
	data->status_icon = NULL;
	data->status_text = NULL;
	data->pCredProvCredentialEvents = NULL;
	data->pCredProvCredential = NULL;
}

void Init()
{
	struct DATA*& data = Get();

	data = (struct DATA*) malloc(sizeof(struct DATA));

	Default();
}

void Deinit()
{
	struct DATA*& data = Get();

	Default();

	free(data);
	data = NULL;
}

HRESULT Initialization(
	/*
	CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE*& pcpgsr,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*& pcpcs, 
	PWSTR*& ppwszOptionalStatusText, 
	CREDENTIAL_PROVIDER_STATUS_ICON*& pcpsiOptionalStatusIcon,
	ICredentialProviderCredentialEvents*& pCredProvCredentialEvents,
	ICredentialProviderCredential* pCredProvCredential
	*/)
{
	DebugPrintLn(__FUNCTION__);

	if (Get() == NULL)
		Init();

	if (Get() == NULL)
		return HOOK_CRITICAL_FAILURE;

	Default();

	/*
	Hook::Serialization::Init(
		pcpgsr,
		pcpcs, 
		ppwszOptionalStatusText, 
		pcpsiOptionalStatusIcon,
		pCredProvCredentialEvents,
		pCredProvCredential);
	*/

	return S_OK;
}

HRESULT EndpointInitialization() 
{ 
	DebugPrintLn(__FUNCTION__);

	if (Endpoint::Get() == NULL)
		Endpoint::Init();

	if (Endpoint::Get() == NULL)
		return HOOK_CRITICAL_FAILURE;

	return S_OK; 
}

HRESULT DataInitialization() 
{ 
	DebugPrintLn(__FUNCTION__);

	if (Data::General::Get()->bypassDataInitialization == true)
	{
		DebugPrintLn("Skipping...");

		Data::General::Get()->bypassDataInitialization = false;
		return S_FALSE;
	}

	if (Data::Gui::Get() == NULL)
		Data::Gui::Init();

	if (Data::Gui::Get() == NULL || Data::Provider::Get() == NULL)
		return HOOK_CRITICAL_FAILURE;

	// copy GUI fields to internal datastructures (we don't want to touch the GUI values)

	switch (General::Fields::GetCurrentUsageScenario())
	{
	case CPUS_LOGON:
	case CPUS_UNLOCK_WORKSTATION:
		if (NOT_EMPTY(Data::Credential::Get()->user_name))
		{
			DebugPrintLn("Loading username from external credential");

			wcscpy_s(Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t), Data::Credential::Get()->user_name);

			if (NOT_EMPTY(Data::Credential::Get()->domain_name))
			{
				DebugPrintLn("Loading domainname from external credential");
				wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);
			}
		}
		else
		{
			DebugPrintLn("Loading username/domainname from GUI");

			Helper::SeparateUserAndDomainName(Serialization::Get()->field_strings[LUFI_OTP_USERNAME],
				Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t),
				Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t)
				);

			if (EMPTY(Data::Gui::Get()->domain_name) && NOT_EMPTY(Data::Credential::Get()->domain_name))
			{
				DebugPrintLn("Loading domainname from external credential, because not provided in GUI");
				wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name); // user's choice has always precedence
			}
		}

		if (NOT_EMPTY(Data::Credential::Get()->password))
		{
			DebugPrintLn("Loading password from external credential");
			wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Data::Credential::Get()->password);
		}
		else
		{
			DebugPrintLn("Loading password from GUI");
			wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_LDAP_PASS]);
		}
		
		DebugPrintLn("Loading OTP from GUI");
		wcscpy_s(Data::Gui::Get()->otp_pass, sizeof(Data::Gui::Get()->otp_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_PASS]);

		DebugPrintLn("Loading OTP #2 from GUI");
		wcscpy_s(Data::Gui::Get()->otp_pass_2, sizeof(Data::Gui::Get()->otp_pass_2) / sizeof(wchar_t), Serialization::Get()->field_strings[LUFI_OTP_PASS_2]);

		break;
	case CPUS_CREDUI:
		/*
		if (NOT_EMPTY(Data::Credential::Get()->user_name))
		{
			DebugPrintLn("Loading username from external credential");

			wcscpy_s(Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t), Data::Credential::Get()->user_name);

			if (NOT_EMPTY(Data::Credential::Get()->domain_name))
			{
				DebugPrintLn("Loading domainname from external credential");
				wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);
			}
		}
		else
		{
		*/
			DebugPrintLn("Loading username/domainname from GUI");

			Helper::SeparateUserAndDomainName(Serialization::Get()->field_strings[CFI_OTP_USERNAME],
				Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t),
				Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t)
				);

			if (EMPTY(Data::Gui::Get()->domain_name) && NOT_EMPTY(Data::Credential::Get()->domain_name))
			{
				DebugPrintLn("Loading domainname from external credential, because not provided in GUI");
				wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name); // user's choice has always precedence
			}
		//}

		if (NOT_EMPTY(Data::Credential::Get()->password))
		{
			DebugPrintLn("Loading password from external credential");
			wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Data::Credential::Get()->password);
		}
		else
		{
			DebugPrintLn("Loading password from GUI");
			wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[CFI_OTP_LDAP_PASS]);
		}

		DebugPrintLn("Loading OTP from GUI");
		wcscpy_s(Data::Gui::Get()->otp_pass, sizeof(Data::Gui::Get()->otp_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[CFI_OTP_PASS]);

		break;
	case CPUS_CHANGE_PASSWORD:
		wcscpy_s(Data::Gui::Get()->user_name, sizeof(Data::Gui::Get()->user_name) / sizeof(wchar_t), Data::Credential::Get()->user_name);
		wcscpy_s(Data::Gui::Get()->domain_name, sizeof(Data::Gui::Get()->domain_name) / sizeof(wchar_t), Data::Credential::Get()->domain_name);

		wcscpy_s(Data::Gui::Get()->ldap_pass, sizeof(Data::Gui::Get()->ldap_pass) / sizeof(wchar_t), Serialization::Get()->field_strings[CPFI_OTP_PASS_OLD]);
		wcscpy_s(Data::Gui::Get()->ldap_pass_new_1, sizeof(Data::Gui::Get()->ldap_pass_new_1) / sizeof(wchar_t), Serialization::Get()->field_strings[CPFI_OTP_PASS_NEW_1]);
		wcscpy_s(Data::Gui::Get()->ldap_pass_new_2, sizeof(Data::Gui::Get()->ldap_pass_new_2) / sizeof(wchar_t), Serialization::Get()->field_strings[CPFI_OTP_PASS_NEW_2]);

		break;
	default:
		return E_INVALIDARG;
	}

	return S_OK;
}

#pragma warning(disable:4702)  
HRESULT EndpointLoadDebugData() 
{ 
	DebugPrintLn(__FUNCTION__);

#ifndef _DEBUG
	return S_FALSE;
#endif

	////
	return S_FALSE;
	////

	OutputDebugStringA("DEBUG: Loading (failing) demo user data John:123456 ..."); OutputDebugStringA("\n");

	wcscpy_s(Endpoint::Get()->username, sizeof(Endpoint::Get()->username) / sizeof(wchar_t), L"John");
	wcscpy_s(Endpoint::Get()->otpPass, sizeof(Endpoint::Get()->otpPass) / sizeof(wchar_t), L"123456"); // will fail
	wcscpy_s(Endpoint::Get()->ldapPass, sizeof(Endpoint::Get()->ldapPass) / sizeof(wchar_t), L"test"); // will fail

	OutputDebugStringA("DEBUG: ... END"); OutputDebugStringA("\n"); 

	return S_OK;
}

HRESULT EndpointLoadData() 
{ 
	DebugPrintLn(__FUNCTION__);

	if (NOT_EMPTY(Data::Gui::Get()->user_name))
	{
		DebugPrintLn("Copy username to epPack");
		wcscpy_s(Endpoint::Get()->username, sizeof(Endpoint::Get()->username) / sizeof(wchar_t), Data::Gui::Get()->user_name);
	}

	if (NOT_EMPTY(Data::Gui::Get()->otp_pass))
	{
		DebugPrintLn("Copy otpPass to epPack");
		wcscpy_s(Endpoint::Get()->otpPass, sizeof(Endpoint::Get()->otpPass) / sizeof(wchar_t), Data::Gui::Get()->otp_pass);
	}

	if (NOT_EMPTY(Data::Gui::Get()->ldap_pass))
	{
		DebugPrintLn("Copy ldapPass to epPack");
		wcscpy_s(Endpoint::Get()->ldapPass, sizeof(Endpoint::Get()->ldapPass) / sizeof(wchar_t), Data::Gui::Get()->ldap_pass);
	}

	if (NOT_EMPTY(Data::Gui::Get()->otp_pass_2))
	{
		DebugPrintLn("Copy otpPass_2 to epPack");
		wcscpy_s(Endpoint::Get()->otpPass_2, sizeof(Endpoint::Get()->otpPass_2) / sizeof(wchar_t), Data::Gui::Get()->otp_pass_2);
	}

	return S_OK; 
}

HRESULT EndpointCallCancelled()
{
	DebugPrintLn(__FUNCTION__);

	Endpoint::Get()->protectMe = false;

	SHStrDupW(L"Logon cancelled", Hook::Serialization::Get()->status_text);

	*Hook::Serialization::Get()->status_icon = CPSI_ERROR;
	*Hook::Serialization::Get()->pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;

	return S_OK;
}

HRESULT EndpointCallSuccessfull() 
{ 
	DebugPrintLn(__FUNCTION__);

	Endpoint::Get()->protectMe = false;

	return S_OK; 
}

HRESULT EndpointCallContinue() 
{ 
	DebugPrintLn(__FUNCTION__);

	Endpoint::Get()->protectMe = true;
	Data::General::Get()->bypassDataDeinitialization = true;

	INIT_ZERO_WCHAR(endpoint_instruction_msg, ENDPOINT_INSTRUCTION_MSG_SIZE);
	INIT_ZERO_WCHAR(instruction_message, ENDPOINT_INSTRUCTION_MSG_SIZE + 100);

	bool *big;

	Endpoint::GetLastInstructionDescription(endpoint_instruction_msg, big);

	if (endpoint_instruction_msg[0] == NULL)
		return S_FALSE;

	if (big)
	{
		swprintf_s(instruction_message, sizeof(instruction_message) / sizeof(wchar_t), L"The endpoint requires further interaction on your side. Code: %X\n\n%s", Endpoint::GetLastErrorCode(), endpoint_instruction_msg);
		SHStrDupW(instruction_message, Hook::Serialization::Get()->status_text);

		*Hook::Serialization::Get()->status_icon = CPSI_SUCCESS;
	}
	else
	{
		///// Concrete Endpoint
		//Data::General::Get()->startEndpointObserver = true;
		Data::General::Get()->clearFields = false;
		/////
		General::Fields::SetScenario(Hook::Serialization::Get()->pCredProvCredential, Hook::Serialization::Get()->pCredProvCredentialEvents, General::Fields::SCENARIO_SECOND_STEP, NULL, endpoint_instruction_msg);
	}

	return S_OK; 
}

HRESULT EndpointCallFailed() 
{
	DebugPrintLn(__FUNCTION__);

	Endpoint::Get()->protectMe = false;

	INIT_ZERO_WCHAR(endpoint_error_msg, ENDPOINT_ERROR_MSG_SIZE);
	INIT_ZERO_WCHAR(error_message, ENDPOINT_ERROR_MSG_SIZE + 100);

	Endpoint::GetLastErrorDescription(endpoint_error_msg);

	swprintf_s(error_message, sizeof(error_message) / sizeof(wchar_t), L"An error occured. Error Code: %X\n\n%s", Endpoint::GetLastErrorCode(), endpoint_error_msg);
	SHStrDupW(error_message, Hook::Serialization::Get()->status_text);

	*Hook::Serialization::Get()->status_icon = CPSI_ERROR;

	return S_OK;
}

HRESULT EndpointDeinitialization() 
{ 
	DebugPrintLn(__FUNCTION__);

	Endpoint::Deinit();

	return S_OK; 
}

HRESULT DataDeinitialization() 
{ 
	DebugPrintLn(__FUNCTION__);

	if (Data::General::Get()->bypassDataDeinitialization == true)
	{
		DebugPrintLn("Skipping...");

		Data::General::Get()->bypassDataDeinitialization = false;
		return S_FALSE;
	}

	Data::Gui::Deinit();

	// Leave provider data intact

	return S_OK; 
}

/////////////

HRESULT ChangePasswordSuccessfull()
{
	SHStrDupW(L"Your password was successfully changed", Hook::Serialization::Get()->status_text);

	*Hook::Serialization::Get()->pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
	*Hook::Serialization::Get()->status_icon = CPSI_SUCCESS;

	return S_OK;
}

/////////////

HRESULT BypassKerberos()
{
	if (SUCCEEDED(Data::Credential::Get()->endpointStatus))
	{
		SHStrDupW(L"Your OTPs were successfully resynchronized", Hook::Serialization::Get()->status_text);

		*Hook::Serialization::Get()->pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		*Hook::Serialization::Get()->status_icon = CPSI_SUCCESS;		
	}
	else
	{
		SHStrDupW(L"Your OTPs could not be resynchronized. Wrong OTPs?", Hook::Serialization::Get()->status_text);

		*Hook::Serialization::Get()->pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
		*Hook::Serialization::Get()->status_icon = CPSI_ERROR;
	}

	return S_OK;
}

HRESULT KerberosCallSuccessfull() { return S_OK; }

HRESULT KerberosCallFailed() { return S_OK; }

/////////////

HRESULT BeforeReturn() 
{ 
	DebugPrintLn(__FUNCTION__);

	Data::Credential::Get()->endpointStatus = E_NOT_SET; // Reset for second run

	Hook::Serialization::Deinit();

	return S_OK; 
}

} // Namespace Serialization

namespace Connect
{

HRESULT ChangePassword()
{
	return E_NOTIMPL;
}

} // Namespace Connect

} // Namespace Hook