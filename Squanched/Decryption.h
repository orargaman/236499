#pragma once


#include "Common.h"
#include "ClientSSL.h"
#include "Config.h"
int decryption_main();
void partialDecrypt(string path, RsaDecryptor& rsaDecryptor);