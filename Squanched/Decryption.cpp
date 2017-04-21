
#include "Decryption.h"
#ifndef ENC

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

int main()
{
	PBYTE masterIV = nullptr, masterKey = nullptr;
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
	string pathToMasters = "";
	std::ifstream masterKeyIVFile;
	masterKeyIVFile.open(pathToMasters, std::ios::binary);
	masterKeyIVFile.read((char*)masterKey, KEY_LEN);
	masterKeyIVFile.read((char*)masterIV, IV_LEN);
	masterKeyIVFile.close();

	string path = "C:\\rans\\236499\\Squanched\\Debug\\rans1.txt" + string(LOCKED_EXTENSION);
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

	//HeapFree(cipher);
	return 0;
}

#endif