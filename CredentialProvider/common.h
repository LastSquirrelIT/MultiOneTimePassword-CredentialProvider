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

#ifndef _PROVIDER_COMMON
#define _PROVIDER_COMMON
#pragma once

//#include <ntsecapi.h>

/*
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>
*/

#include "guid.h"
#include "lang.h"
#include "resource.h"
//#include "data.h"
//#include "helper.h"

#include "scenario_unlock_logon.h"
#include "scenario_change_password.h"
#include "scenario_credui.h"

#define MAX_NUM_FIELDS 9

#define MAX_ULONG  ((ULONG)(-1))

#define ZERO(NAME) \
	ZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME)

#define NOT_EMPTY(NAME) \
	(NAME != NULL && NAME[0] != NULL)

#define EMPTY(NAME) \
	(NAME == NULL || NAME[0] == NULL)

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* s_rgCredProvFieldDescriptorsFor[] =
{
	NULL,												// CPUS_INVALID = 0x0000,
	s_rgScenarioLogonUnlockCredProvFieldDescriptors,	// CPUS_LOGON,
	s_rgScenarioLogonUnlockCredProvFieldDescriptors,	// CPUS_UNLOCK_WORKSTATION,
	s_rgScenarioChangePasswordCredProvFieldDescriptors,	// CPUS_CHANGE_PASSWORD,
	s_rgScenarioCredUiCredProvFieldDescriptors,			// CPUS_CREDUI,
	NULL,												// CPUS_PLAP,
};

static const FIELD_INITIALIZOR* s_rgCredProvFieldInitializorsFor[] =
{
	NULL,											// CPUS_INVALID = 0x0000,
	s_rgScenarioLogonUnlockFieldInitializors,		// CPUS_LOGON,
	s_rgScenarioLogonUnlockFieldInitializors,		// CPUS_UNLOCK_WORKSTATION,
	s_rgScenarioChangePasswordFieldInitializors,	// CPUS_CHANGE_PASSWORD,
	s_rgScenarioCredUiFieldInitializors,			// CPUS_CREDUI,
	NULL,											// CPUS_PLAP
};

static const unsigned int s_rgCredProvNumFieldsFor[] =
{
	0,					// CPUS_INVALID = 0x0000,
	LUFI_NUM_FIELDS,	// CPUS_LOGON,
	LUFI_NUM_FIELDS,	// CPUS_UNLOCK_WORKSTATION,
	CPFI_NUM_FIELDS,	// CPUS_CHANGE_PASSWORD,
	CFI_NUM_FIELDS,		// CPUS_CREDUI,
	0,					// CPUS_PLAP
};

static const FIELD_STATE_PAIR* s_rgCredProvBaseFieldStatePairsFor[] =
{
	NULL,											// CPUS_INVALID = 0x0000,
	s_rgScenarioLogonUnlockFieldStatePairs,			// CPUS_LOGON,
	s_rgScenarioLogonUnlockFieldStatePairsUnlock,	// CPUS_UNLOCK_WORKSTATION,
	s_rgScenarioChangePasswordFieldStatePairs,		// CPUS_CHANGE_PASSWORD,
	s_rgScenarioCredUiFieldStatePairs,				// CPUS_CREDUI,
	NULL,											// CPUS_PLAP
};

#endif
