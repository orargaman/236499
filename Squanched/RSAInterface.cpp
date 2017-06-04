#include "RSAInterface.h"

class Base64Item
{
public:
	vector<BYTE> vByte;
	Base64Item(const string& s) : vByte(base64_decode(s)) {}
};

static wchar_t *convertCharArrayToLPCWSTR(const char* charArray, const size_t size)
{
	wchar_t* wString = new wchar_t[size];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, size);
	return wString;
}

static DWORD MSBByteVectorToDword(const vector<BYTE>& by)
{
	DWORD value = 0;
	for (size_t i = 0; i < by.size(); i++)
	{
		value = (value << 8) + (by[i] & 0xff);
	}
	return value;
}

static void copyReversed(vector<BYTE> BinMSB, PBYTE BinDst)
{
	
	for (size_t i = 0; i < BinMSB.size(); ++i)
		BinDst[i] = BinMSB[BinMSB.size() - 1 - i];
}

static bool init_key(PBYTE blob, DWORD blobSize, HCRYPTPROV& hCryptProv, HCRYPTKEY& hKey)
{
	if (!CryptAcquireContext(
		&hCryptProv,
		NULL,
		MS_ENHANCED_PROV,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))
	{
		std::cout << "Error on CryptAcquireContext " << GetLastError() << std::endl;
		goto init_CLEANUP;
	}
	if (!CryptImportKey(
		hCryptProv,
		blob,
		blobSize,
		NULL,
		0,
		&hKey))
	{
		std::cout << "Error on CryptImportKey " << GetLastError() << std::endl;
		goto init_CLEANUP;
	}
	return true;
init_CLEANUP:
	if (hCryptProv)
	{
		CryptReleaseContext(hCryptProv, 0);
		hCryptProv = NULL;
	}
	if (hKey)
	{
		CryptDestroyKey(hKey);
		hKey = NULL;
	}
	return false;
}

PBYTE RsaEncryptor::encrypt(PBYTE msg, DWORD dwDataLen)
{
	const DWORD cdwDataLen = 128;
	PBYTE pMsg = (PBYTE) HeapAlloc(GetProcessHeap(), 0, cdwDataLen);
	memcpy(pMsg, msg, dwDataLen);
	/*HCRYPTKEY keyDup;
	if(!CryptDuplicateKey(hKey,0,0,&keyDup))
	{
		std::cout << "Error on CryptDuplicateKey " << GetLastError() << std::endl;
		goto RSA_ENC_CLEANUP;
	}*/
	if (!CryptEncrypt(this->hKey, NULL, FALSE, CRYPT_OAEP, pMsg, &dwDataLen, cdwDataLen))
	{
		std::cout << "Error on CryptEncrypt " << GetLastError() << std::endl;
		goto RSA_ENC_CLEANUP;
	}
	goto RSA_GOOD_RETURN;
RSA_ENC_CLEANUP:
	HeapFree(GetProcessHeap(), 0, pMsg);
	pMsg = nullptr;
RSA_GOOD_RETURN:
	//CryptDestroyKey(keyDup);
	return pMsg;
}

void RsaEncryptor::init_Encryptor(const string& sMod, const string& sExp)
{
	Base64Item mod = sMod;
	Base64Item exp = sExp;

	const DWORD modulusLengthInBytes = 128;
	DWORD keyBlobLength = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + modulusLengthInBytes;
	BYTE* keyBlob = (PBYTE)malloc(keyBlobLength);
	BLOBHEADER* blobheader = (BLOBHEADER*)keyBlob;
	blobheader->bType = PUBLICKEYBLOB;
	blobheader->bVersion = CUR_BLOB_VERSION;
	blobheader->reserved = 0;
	blobheader->aiKeyAlg = CALG_RSA_KEYX;
	RSAPUBKEY* rsapubkey = (RSAPUBKEY*)(keyBlob + sizeof(BLOBHEADER));
	rsapubkey->magic = 0x31415352;
	rsapubkey->bitlen = modulusLengthInBytes * 8;
	rsapubkey->pubexp = MSBByteVectorToDword(exp.vByte);         // Or whatever your public exponent is.
	BYTE* modulus = keyBlob + sizeof(BLOBHEADER) + sizeof(RSAPUBKEY);
	copyReversed(mod.vByte, modulus);//
	init_key(keyBlob, keyBlobLength, hCryptProv, hKey);
}

RsaEncryptor::RsaEncryptor() : hCryptProv(NULL), hKey(NULL) {}

RsaEncryptor::~RsaEncryptor()
{
	CryptReleaseContext(hCryptProv, 0);
	hCryptProv = NULL;
	CryptDestroyKey(hKey);
	hKey = NULL;
}

PBYTE RsaDecryptor::decrypt(PBYTE encMsg, DWORD length)
{
	PBYTE bBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, length);
	if (!bBuffer)
	{
		std::cout << "Error allocating buffer for decryption" << std::endl;
		return NULL;
	}
	for (size_t i = 0; i < length; ++i)
	{
		bBuffer[i] = encMsg[i];
	}

	//now to get the decryption thing going
		if (!CryptDecrypt(hKey, NULL, TRUE, CRYPT_OAEP, bBuffer, &length))
	{
		std::cout << "Error on CryptDecrypt: " << GetLastError() << std::endl;
		goto CLEANUP;
	}
		return bBuffer;
	
	
CLEANUP:
	HeapFree(GetProcessHeap(), 0, bBuffer);
	return NULL;
}

void RsaDecryptor::init_Decryptor(const StringPrivateBlob& sBlob)
{
	Base64Item mod = sBlob.smod;
	Base64Item exp = sBlob.sexp;
	Base64Item P = sBlob.sP;
	Base64Item Q = sBlob.sQ;
	Base64Item DP = sBlob.sDP;
	Base64Item DQ = sBlob.sDQ;
	Base64Item InverseQ = sBlob.sInverseQ;
	Base64Item D = sBlob.sD;

	DWORD offset = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY); // to keep track of things;
	const DWORD modulusLengthInBytes = 128;
	DWORD keyBlobLength = sizeof(BLOBHEADER) + sizeof(RSAPUBKEY) + (modulusLengthInBytes * 4) + (modulusLengthInBytes / 2);//TODO figure out size
	BYTE* keyBlob = (PBYTE)malloc(keyBlobLength);
	BLOBHEADER* blobheader = (BLOBHEADER*)keyBlob;
	blobheader->bType = PRIVATEKEYBLOB;
	blobheader->bVersion = CUR_BLOB_VERSION;
	blobheader->reserved = 0;
	blobheader->aiKeyAlg = CALG_RSA_KEYX;
	RSAPUBKEY* rsapubkey = (RSAPUBKEY*)(keyBlob + sizeof(BLOBHEADER));
	rsapubkey->magic = 0x32415352;
	rsapubkey->bitlen = modulusLengthInBytes * 8 ;
	rsapubkey->pubexp = MSBByteVectorToDword(exp.vByte);
	
	BYTE* modulus = keyBlob + offset;
	copyReversed(mod.vByte, modulus);
	offset += modulusLengthInBytes;
	BYTE* prime1 = keyBlob + offset ;
	copyReversed(P.vByte, prime1);
	offset += modulusLengthInBytes / 2;
	BYTE* prime2 = keyBlob + offset;
	copyReversed(Q.vByte, prime2);
	offset += (modulusLengthInBytes / 2);
	BYTE* exponent1 = keyBlob + offset;
	copyReversed(DP.vByte, exponent1);
	offset += (modulusLengthInBytes / 2);
	BYTE* exponent2 = keyBlob + offset;
	copyReversed(DQ.vByte, exponent2);
	offset += (modulusLengthInBytes / 2);
	BYTE* coefficient = keyBlob + offset;
	copyReversed(InverseQ.vByte, coefficient);
	offset += modulusLengthInBytes / 2;
	BYTE* privateExponent = keyBlob + offset;
	copyReversed(D.vByte, privateExponent);
	
	init_key(keyBlob, keyBlobLength, hCryptProv, hKey);
}

RsaDecryptor::RsaDecryptor() : hCryptProv(NULL), hKey(NULL) {}

RsaDecryptor::~RsaDecryptor()
{
	CryptReleaseContext(hCryptProv, 0);
	hCryptProv = NULL;
	CryptDestroyKey(hKey);
	hKey = NULL;
}
/*
USAGE EXAMPLE
int main()
{
	string mod;// = "yVUndgQFuB5Z5FgC0/WgWCg6Y8VuB582avGjQDdeoJDa1+RBKCyXo700sAMSGjM/bVakOlFqvCsVFNBysx1CH731CDb2DR1a0bsmYmDQ9d0ZHX+AOohVDIx9mc7bkDQZoEFpe9NqFsu95Y9yktpl1JKPmKyLOFgufGJYYvQyoOM=";
	string exp;// = "AQAB";
	string P;// = "/JydNn89lSWjgWOG1XRJm1qTWDekzzoLfTQU+GK+h8DGQ6gkUbgqGosLGo+eAxbO/ETZV3ibbBuIdvL4UxC5Qw==";
	string Q;// = "zAh23Gc8Oqz/Uh2wh+yt8DqUesVLwMn2koc9CbyF9/Z5Qe8OIR4yygJtuYruRC1x/KYj85l6DGzstUZOtYmv4Q==";
	string DP;// = "+1INj1SUPjjOLUKJuQAS4z7/7PqfO5RyLcSNQHltOb5vAozcZXkmWnYPPAO6nzQoBg+xdDcH2kyiPkWJDYtL5Q==";
	string DQ;// = "cbYh8HJEufrijTRox0hcJG+xgr7kmjy1BDMFDKEaFPkz2VBPEpwO+FDkMC1C35JoXcOGc+RMhhJK1jip8zkaYQ==";
	string InverseQ;// = "3PAXzlAXgvLVrbOEygjA2zhJEYALBEi6VTKqfDKlnv8/D9QUkC39bEDIRLG0wMFFxN8NlLx5zTiiVswxnMy8Mw==";
	string D;// = "KKBSyKkyID+bowyxcWUAuJlRgv19YPNbL0RYTWZ+5UalqmfoT/uDk+pjndrYxcmulFkl5ZC1SYgmBl+zrXoLc/Ei86BtNiuwfcqHlUDp0fdP+fyYN45wh/251HQ3UM1zBpMP8XeYB6zjpCU/s3/wCBE6WpJWN9fKcG0W5PLq8eE=";
	string strPUB = R"(<RSAKeyValue><Modulus>yVUndgQFuB5Z5FgC0/WgWCg6Y8VuB582avGjQDdeoJDa1+RBKCyXo700sAMSGjM/bVakOlFqvCsVFNBysx1CH731CDb2DR1a0bsmYmDQ9d0ZHX+AOohVDIx9mc7bkDQZoEFpe9NqFsu95Y9yktpl1JKPmKyLOFgufGJYYvQyoOM=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>)";
	string strPRV = R"(<RSAKeyValue><Modulus>yVUndgQFuB5Z5FgC0/WgWCg6Y8VuB582avGjQDdeoJDa1+RBKCyXo700sAMSGjM/bVakOlFqvCsVFNBysx1CH731CDb2DR1a0bsmYmDQ9d0ZHX+AOohVDIx9mc7bkDQZoEFpe9NqFsu95Y9yktpl1JKPmKyLOFgufGJYYvQyoOM=</Modulus><Exponent>AQAB</Exponent><P>/JydNn89lSWjgWOG1XRJm1qTWDekzzoLfTQU+GK+h8DGQ6gkUbgqGosLGo+eAxbO/ETZV3ibbBuIdvL4UxC5Qw==</P><Q>zAh23Gc8Oqz/Uh2wh+yt8DqUesVLwMn2koc9CbyF9/Z5Qe8OIR4yygJtuYruRC1x/KYj85l6DGzstUZOtYmv4Q==</Q><DP>+1INj1SUPjjOLUKJuQAS4z7/7PqfO5RyLcSNQHltOb5vAozcZXkmWnYPPAO6nzQoBg+xdDcH2kyiPkWJDYtL5Q==</DP><DQ>cbYh8HJEufrijTRox0hcJG+xgr7kmjy1BDMFDKEaFPkz2VBPEpwO+FDkMC1C35JoXcOGc+RMhhJK1jip8zkaYQ==</DQ><InverseQ>3PAXzlAXgvLVrbOEygjA2zhJEYALBEi6VTKqfDKlnv8/D9QUkC39bEDIRLG0wMFFxN8NlLx5zTiiVswxnMy8Mw==</InverseQ><D>KKBSyKkyID+bowyxcWUAuJlRgv19YPNbL0RYTWZ+5UalqmfoT/uDk+pjndrYxcmulFkl5ZC1SYgmBl+zrXoLc/Ei86BtNiuwfcqHlUDp0fdP+fyYN45wh/251HQ3UM1zBpMP8XeYB6zjpCU/s3/wCBE6WpJWN9fKcG0W5PLq8eE=</D></RSAKeyValue>)";
	parsePublicKey(strPUB, mod, exp);
	parsePrivateKey(strPRV, mod, exp, P, Q, DP, DQ, InverseQ, D);
	StringPrivateBlob sBlob = { mod, exp, P, Q, DP, DQ, InverseQ, D };
	
	char* msg = "this is a message";
	int msgLen = 18;
	char* msg2 = "this is another message";
	int msg2Len = 24;
	RsaEncryptor enc;
	enc.init_Encryptor(mod, exp);
	PBYTE encMsg = enc.encrypt((PBYTE)msg, msgLen);
	PBYTE encMsg2 = enc.encrypt((PBYTE)msg2, msg2Len);
	RsaDecryptor dec;
	dec.init_Decryptor(sBlob);
	PBYTE decMsg = dec.decrypt(encMsg, 128);
	PBYTE decMsg2 = dec.decrypt(encMsg2, 128);

	return 0;
}
*/
