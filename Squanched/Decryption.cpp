
#include "Decryption.h"
#ifndef ENC
void DecryptData(string path, PBYTE key, PBYTE iv, PBYTE CipherText, DWORD CipherTextLength, BYTE paddingSize)
{
	DWORD status;
	PBYTE   TempInitVector = NULL;
	DWORD   TempInitVectorLength = 0;
	DWORD   ResultLength = 0;

	BCRYPT_ALG_HANDLE aesHandle = nullptr;
	status = BCryptOpenAlgorithmProvider(&aesHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	ULONG res;
	char blockLen[50] = { 0 };
	status = BCryptGetProperty(aesHandle, BCRYPT_BLOCK_LENGTH, (PUCHAR)blockLen, 50, &res, 0);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}
	//TODO verify compatible block length
	BCRYPT_KEY_HANDLE keyHandle;

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
		//TODO cleanup
	}
	status = BCryptSetProperty(keyHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) {
		//TODO cleanup
	}

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
	string path = "C:\\rans\\236499\\Squanched\\Debug\\rans1.txt" + string(LOCKED_EXTENSION);
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
	ifile.read((char*)iv, IV_LEN);
	ifile.read((char*)key, KEY_LEN);
	ifile.read((char*)cipher, cipherSize);
	DecryptData(path,key,iv,cipher,cipherSize, paddingSize);

	//HeapFree(cipher);
	return 0;
}

#endif