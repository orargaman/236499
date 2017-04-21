#pragma once
/*
* Extension for all locked files
*/
#define LOCKED_EXTENSION ".locked"

/*
* Key length in bytes, default is 32 (256 bits)
*/
#define KEY_LEN (256/8) // 256 bits

/*
* URL to add.php
*/
#define URL_PANEL "http://localhost/add.php"

/*
* If notification file should be created
*/
#define OPEN_FILE true

/*
* Notification file name
*/
#define NOTIFY_FILENAME "note.html"

#define IV_LEN (128/8)