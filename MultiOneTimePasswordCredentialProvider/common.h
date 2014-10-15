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

#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#include "lang.h"

#define MAX_ULONG  ((ULONG)(-1))

#define ZERO(NAME) \
	ZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME)

// The indexes of each of the fields in our credential provider's appended tiles.
enum SAMPLE_FIELD_ID 
{
    SFI_OTP_LOGO			= 0,
	SFI_OTP_LARGE_TEXT		= 1,
	SFI_OTP_SMALL_TEXT		= 2,
	SFI_OTP_USERNAME		= 3,
	SFI_OTP_LDAP_PASS		= 4,
	SFI_OTP_LDAP_PASS_NEW_1	= 5,
	SFI_OTP_LDAP_PASS_NEW_2	= 6,
    SFI_OTP_PASS			= 7,
	SFI_OTP_SUBMIT_BUTTON	= 8,
	SFI_NUM_FIELDS          = 9,
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs 
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when 
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] = 
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// SFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_LDAP_PASS_NEW_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_LDAP_PASS_NEW_2
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_SUBMIT_BUTTON
};

static const FIELD_STATE_PAIR s_rgFieldStatePairsUnlock[] = 
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_LARGE_TEXT
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_SMALL_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// SFI_OTP_LDAP_PASS
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_LDAP_PASS_NEW_1
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_LDAP_PASS_NEW_2
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_SUBMIT_BUTTON
};

static const FIELD_STATE_PAIR s_rgFieldStatePairsChangePassword[] = 
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_LOGO
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },					// SFI_OTP_LARGE_TEXT
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_SMALL_TEXT
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_USERNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },		// SFI_OTP_LDAP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_LDAP_PASS_NEW_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_LDAP_PASS_NEW_2
	{ CPFS_HIDDEN, CPFIS_NONE },							// SFI_OTP_PASS
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },			// SFI_OTP_SUBMIT_BUTTON
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
	{ SFI_OTP_LOGO,				CPFT_TILE_IMAGE,		L"OpenOTPLogo" },
	{ SFI_OTP_LARGE_TEXT,		CPFT_LARGE_TEXT,		L"LargeText" },
	{ SFI_OTP_SMALL_TEXT,		CPFT_SMALL_TEXT,		L"SmallText" },
	{ SFI_OTP_USERNAME,			CPFT_EDIT_TEXT,			L"Username" },
	{ SFI_OTP_LDAP_PASS,		CPFT_PASSWORD_TEXT,		L"Password" },
	{ SFI_OTP_LDAP_PASS_NEW_1,	CPFT_PASSWORD_TEXT,		L"New Password" },
	{ SFI_OTP_LDAP_PASS_NEW_2,	CPFT_PASSWORD_TEXT,		L"Repeat New Password" },
	{ SFI_OTP_PASS,				CPFT_EDIT_TEXT,			L"One-Time Password" },
	{ SFI_OTP_SUBMIT_BUTTON,	CPFT_SUBMIT_BUTTON,		L"Submit" },
};
