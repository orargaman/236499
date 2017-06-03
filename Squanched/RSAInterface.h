#pragma once
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <Wincrypt.h>

#include <string>
#include <vector>
#include "base64.h"
using std::string;
using std::vector;
void parsePublicKey(string str, string& mod, string& exp);

struct StringPrivateBlob
{
	//all in 64Base as given by xml description
	string smod;
	string sexp;
	string sP;
	string sQ;
	string sDP;
	string sDQ;
	string sInverseQ;
	string sD;
};

class RsaEncryptor
{
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
public:
	RsaEncryptor();
	//both in 64Base, as given by xml description
	void init_Encryptor(const string& sModulus, const string& sExp);
	//returned buffer is alloc'd with heapAlloc.
	PBYTE encrypt(PBYTE msg, DWORD length);
	~RsaEncryptor();
};

class RsaDecryptor
{
	HCRYPTPROV hCryptProv;
	HCRYPTKEY hKey;
public:
	RsaDecryptor();
	//both in 64Base, as given by xml description
	void init_Decryptor(const StringPrivateBlob&);
	//returned buffer is alloc'd with heapAlloc, original msg stays as is
	PBYTE decrypt(PBYTE msg, DWORD length = 128);
	~RsaDecryptor();
};
