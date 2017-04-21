#include "Utils.h"
#include <iostream>
#include <string>



void iterate(const path& parent) {
	string path;
	directory_iterator end_itr;

	for (directory_iterator itr(parent); itr != end_itr; ++itr) {
		path = itr->path().string();

		if (is_directory(itr->status()) && !symbolic_link_exists(itr->path())) {
			iterate(path);
		}
		else {
			process(path);
		}
	}
}


void process(const path& path) {
	std::cout << "processing " << path.string() << std::endl;
	//encrypt(path.string());
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
