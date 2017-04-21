#pragma once

#include <boost/filesystem/operations.hpp>

using namespace boost::filesystem;
using std::string;

void iterate(const path& parent);
void process(const path& path);
size_t getFileSize(const string path);
