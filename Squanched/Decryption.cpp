
#include "Decryption.h"


#if 0
std::string hex_to_string(const std::string& input);
DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);

Status DecryptKeyIV(PBYTE keyIV, PBYTE* keyIVBuff,  PBYTE masterKey, PBYTE masterIV)
{
	Status status;
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	BCRYPT_KEY_HANDLE keyHandle;
	PBYTE tmpIv = nullptr;
	status = getKeyHandle(masterKey, keyHandle, aesHandle);
	if (!NT_SUCCESS(status)) {
		goto DEC_KEY_IV_CLEAN;
	}
	DWORD  resSize;
	//CHECK IF NEEDED V
	tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (NULL == tmpIv) {
		goto DEC_KEY_IV_CLEAN;
	}
	memcpy(tmpIv, masterIV, IV_LEN);
	status = BCryptDecrypt(keyHandle, keyIV, KEY_LEN + IV_LEN, nullptr, tmpIv, IV_LEN, *keyIVBuff, KEY_LEN + IV_LEN, &resSize, 0);
	if (!NT_SUCCESS(status)) {
		goto DEC_KEY_IV_CLEAN;
	}
DEC_KEY_IV_CLEAN:
	if(tmpIv)
		HeapFree(GetProcessHeap(), 0, tmpIv);

	return status;
}

Status getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle)
{
	Status status;
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
	PBYTE plainText = nullptr;
	PBYTE tmpIv = nullptr;
	std::ofstream ofile;
	BCRYPT_KEY_HANDLE keyHandle;
	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	string plainPath = path, ext = string(LOCKED_EXTENSION);
	string::size_type i = plainPath.find(ext);
	status = getKeyHandle(key, keyHandle, aesHandle);
	if(!NT_SUCCESS(status))
	{
		goto DECCLEAN;
	}
	DWORD plainSize, resSize;
	//CHECK IF NEEDED V
	tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (NULL == tmpIv) {
		goto DECCLEAN;
	}
	memcpy(tmpIv, iv, IV_LEN);
	status = BCryptDecrypt(keyHandle, CipherText, CipherTextLength, NULL, tmpIv, IV_LEN, NULL, 0, &plainSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto DECCLEAN;
	}
	plainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, plainSize);
	if (NULL == plainText) {
		goto DECCLEAN;
	}
	status = BCryptDecrypt(keyHandle, CipherText, CipherTextLength, NULL, tmpIv, IV_LEN, plainText, plainSize, &resSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto DECCLEAN;
	}
#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif
	
	if(string::npos != i)
	{
		plainPath.erase(i, ext.length());
	}
	
	ofile = std::ofstream(plainPath.c_str(), std::ios::binary);
	ofile.write((char*)plainText, plainSize - paddingSize);
	ofile.close();
DECCLEAN:
	if (tmpIv)
		HeapFree(GetProcessHeap(), 0, tmpIv);
	if (plainText)
		HeapFree(GetProcessHeap(), 0, plainText);

}

void decrypt_wrapper(string path, PBYTE masterIV, PBYTE masterKey)
{
	std::ifstream ifile;
	PBYTE keyIV = nullptr, keyIVBuff = nullptr, iv = nullptr, key = nullptr, cipher = nullptr;
	Status status;
	if (!do_decrypt(path)) return;
	keyIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	if (keyIV == nullptr) goto CLEAN;
	keyIVBuff = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	if (keyIVBuff == nullptr) goto CLEAN;
	iv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (iv == nullptr) goto CLEAN;
	key = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN);
	if (key == nullptr) goto CLEAN;
	size_t cipherSize = getFileSize(path) - IV_LEN - KEY_LEN - IV_DIGITS_NUM;
	cipher = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cipherSize);
	if (cipher == nullptr) goto CLEAN;
	
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
	status = DecryptKeyIV(keyIV, &keyIVBuff, masterKey, masterIV);
	if(!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	memcpy(key, keyIVBuff, KEY_LEN);
	memcpy(iv, keyIVBuff + KEY_LEN, IV_LEN);
	DecryptData(path,key,iv,cipher,cipherSize, paddingSize);
CLEAN:
	if (keyIV)
		HeapFree(GetProcessHeap(), 0, keyIV);
	if (keyIVBuff)
		HeapFree(GetProcessHeap(), 0, keyIVBuff);
	if (iv)
		HeapFree(GetProcessHeap(), 0, iv);
	if (key)
		HeapFree(GetProcessHeap(), 0, key);
	if (cipher)
		HeapFree(GetProcessHeap(), 0, cipher);
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
	std::string id;
	Status status;
	string path = ROOT_DIR;
	string pathToID = get_home() + R"(\SquanchedID.id)";
	std::ifstream idFile;
	string sMasterIV, sMasterKey;

//	string pathToMasters = "C:\\rans\\236499\\Squanched\\Debug\\KEY-IV.txt";
//	std::ifstream masterKeyIVFile;
//	masterKeyIVFile.open(pathToMasters, std::ios::binary);
//	masterKeyIVFile.read((char*)masterKey, KEY_LEN);
//	masterKeyIVFile.read((char*)masterIV, IV_LEN);
//	masterKeyIVFile.close();
	
	
	idFile.open(pathToID, std::ios::binary);
	id = std::string((std::istreambuf_iterator<char>(idFile)), (std::istreambuf_iterator<char>()));
	idFile.close();
	id = string_to_hex(id);
	
	status = getFromServer(id, sMasterIV, sMasterKey);
	if(!NT_SUCCESS(status))
	{
		return -1;
	}
	sMasterIV = hex_to_string(sMasterIV);
	sMasterKey = hex_to_string(sMasterKey);
	masterIV = (BYTE*)sMasterIV.c_str();
	masterKey = (BYTE*)sMasterKey.c_str();
	
	iterate(path, &decrypt_wrapper, masterIV, masterKey);

	//HeapFree(cipher);

	return 0;
}

#endif