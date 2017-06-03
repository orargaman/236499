#pragma once

#define  _WIN32_WINNT 0x0500
#include <windows.h>

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
#include "RSAInterface.h"
#ifdef _WIN32
#	include <Urlmon.h>
#	include <Lmcons.h>
#else
#	include <pwd.h>
#endif
typedef DWORD Status;