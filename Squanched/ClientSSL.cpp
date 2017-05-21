#pragma once
#include "ClientSSL.h"

using std::string;

Status SendToServer(string str)
{
	CURL *curl;
	CURLcode res;
	Status status = STATUS_SUCCESS;
	
	curl_global_init(CURL_GLOBAL_DEFAULT);
	string url = "https://squanchedhttpexample.azurewebsites.net\
/api/HttpTriggerCSharp1?code=7t9bdLoOFKklk/8I6vz6RfP7xHGGJ98xTwBueYcIleoxXVgNPzbwOQ==&&";
	url += str;

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		//TODO else set status fail

#ifdef SKIP_PEER_VERIFICATION
		/*
		* If you want to connect to a site who isn't using a certificate that is
		* signed by one of the certs in the CA bundle you have, you can skip the
		* verification of the server's certificate. This makes the connection
		* A LOT LESS SECURE.
		*
		* If you have a CA cert for the server stored someplace else than in the
		* default bundle, then the CURLOPT_CAPATH option might come handy for
		* you.
		*/
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
		/*
		* If the site you're connecting to uses a different host name that what
		* they have mentioned in their server certificate's commonName (or
		* subjectAltName) fields, libcurl will refuse to connect. You can skip
		* this check, but this will make the connection less secure.
		*/
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));
			//TODO SET status FAIL

		/* always cleanup */
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();

	return status;
}


struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t

WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

std::string hex_to_string(const std::string& input)
{
	static const char* const lut = "0123456789ABCDEF";
	size_t len = input.length();
	if (len & 1) throw std::invalid_argument("odd length");

	std::string output;
	output.reserve(len / 2);
	for (size_t i = 0; i < len; i += 2)
	{
		char a = input[i];
		const char* p = std::lower_bound(lut, lut + 16, a);
		if (*p != a) throw std::invalid_argument("not a hex digit");

		char b = input[i + 1];
		const char* q = std::lower_bound(lut, lut + 16, b);
		if (*q != b) throw std::invalid_argument("not a hex digit");

		output.push_back(((p - lut) << 4) | (q - lut));
	}
	return output;
}

Status getFromServer(string id, PBYTE& IV, PBYTE& key)
{
	Status status = STATUS_SUCCESS;

	CURL *curl_handle;
	CURLcode res;

	struct MemoryStruct chunk;

	chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

	/* init the curl session */
	curl_handle = curl_easy_init();

	string url = "https://squanchedhttpexample.azurewebsites.net\
/api/httpRetrieveKeyIV?code=yJ6KMPb/gnZev9K41RV0i1dCjcqJpXHwzjUa7Qq7Llm54cDYTnXvTA==";
	url += "&&ID="+id;
	/* specify URL to get */
	curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());

	/* send all data to this function  */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

	/* we pass our 'chunk' struct to the callback function */
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

	/* some servers don't like requests that are made without a user-agent
	field, so we provide one */
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

	/* get it! */
	res = curl_easy_perform(curl_handle);

	/* check for errors */
	if (res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n",
			curl_easy_strerror(res));
		//TODO Handle status
	}
	else {
		/*
		* Now, our chunk.memory points to a memory block that is chunk.size
		* bytes big and contains the remote file.
		*
		* Do something nice with it!
		*/

		printf("%lu bytes retrieved\n", (long)chunk.size);
		string sKey, sIV;
		sIV.assign((char*)(chunk.memory) + 1, IV_LEN*2);
		sKey.assign((char*)(chunk.memory) + IV_LEN*2+1, KEY_LEN*2);
		sIV = hex_to_string(sIV);
		sKey = hex_to_string(sKey);
		key = (BYTE*)sKey.c_str();
		IV = (BYTE*)sIV.c_str();

		/* cleanup curl stuff */
		curl_easy_cleanup(curl_handle);
	}



	free(chunk.memory);

	/* we're done with libcurl, so clean it up */
	curl_global_cleanup();

	return status;
}