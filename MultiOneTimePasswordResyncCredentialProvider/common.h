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
#include "lang.h"

#define ZERO(NAME) \
	ZeroMemory(NAME, sizeof(NAME))

#define INIT_ZERO_WCHAR(NAME, SIZE) \
	wchar_t NAME[SIZE]; \
	ZERO(NAME)

#define INIT_ZERO_CHAR(NAME, SIZE) \
	char NAME[SIZE]; \
	ZERO(NAME)

// The indexes of each of the fields in our credential provider's tiles.
enum SAMPLE_FIELD_ID 
{
    SFI_TILEIMAGE       = 0,
    SFI_PROVNAME        = 1,
	SFI_USERNAME        = 2,
    SFI_OTP_1           = 3,
	SFI_OTP_2           = 4,
    SFI_SUBMIT_BUTTON   = 5, 
    SFI_NUM_FIELDS      = 6,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
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
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },       // SFI_TILEIMAGE
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },       // SFI_PROVNAME
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },       // SFI_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_OTP_1
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_OTP_2
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },       // SFI_SUBMIT_BUTTON   
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,     CPFT_TILE_IMAGE,    L"Image"                   },
    { SFI_PROVNAME,      CPFT_LARGE_TEXT,    L"Providername"            },
	{ SFI_USERNAME,      CPFT_EDIT_TEXT,     I18N_CAPTION_EDIT_USERNAME },
    { SFI_OTP_1,         CPFT_PASSWORD_TEXT, I18N_CAPTION_EDIT_OTP1     },
	{ SFI_OTP_2,         CPFT_PASSWORD_TEXT, I18N_CAPTION_EDIT_OTP2     },
    { SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit"                  },
};
