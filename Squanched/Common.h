#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <boost/filesystem/operations.hpp>
#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h>
#include <sal.h>
#include "Config.h"
#include "Utils.h"
#include <iostream>
#include <fstream>
#ifdef _WIN32
#	include <Urlmon.h>
#	include <Lmcons.h>
#else
#	include <pwd.h>
#endif
typedef DWORD Status;