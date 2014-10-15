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

#include <Windows.h>
#include "conversions.h"
#include "registry.h"

#define LOGGING true

#define DEFAULT_TIMEOUT_SEC 3

#define DIR_SEP   L"\\"
#define PARAM_SEP L" "

//#define CEMOTP_DIR L"C:\\multiotp"
#define CEMOTP_EXE L"multiotp.exe"

#define CEMOTP_PARAM_LOG    L"-log"
#define CEMOTP_PARAM_RESYNC L"-resync"

#define CEMOTP_EXIT_SUCCESS      0
#define CEMOTP_EXIT_RESYNC_OK    14
#define CEMOTP_EXIT_ERROR_LOCKED 24
#define CEMOTP_EXIT_ERROR_AUTH   99

DWORD __CallMultiOTPExe(char* path_to_multiotp, int argc, wchar_t *argv[]);
