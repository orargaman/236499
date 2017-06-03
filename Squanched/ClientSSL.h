#pragma once
#include <stdio.h>
#include <curl/curl.h>
#include <string>
#include "Common.h"
#define SKIP_HOSTNAME_VERIFICATION
#define SKIP_PEER_VERIFICATION
Status SendToServer(string str);
Status getFromServer(string url, string& str);
bool download_jpeg(string path, char* url);

