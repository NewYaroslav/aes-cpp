# AES
C++ AES(Advanced Encryption Standard) implementation  
 
![Build Status](https://github.com/NewYaroslav/AES/actions/workflows/aes-ci.yml/badge.svg?branch=main)

## Prerequisites
* C++ compiler
* CMake 2.8 or newer

## Supported Modes
ECB, CBC, CFB, CTR and GCM modes are implemented. GCM additionally produces an authentication tag for message integrity.

## Vector Overloads
All encryption and decryption methods have overloads that accept `std::vector<unsigned char>` in addition to raw pointer APIs:
```c++
std::vector<unsigned char> plainVec = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
std::vector<unsigned char> keyVec   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char iv[]                  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

AES aesVec(AESKeyLength::AES_128);
auto cipherVec = aesVec.EncryptCBC(plainVec, keyVec, iv);
```

## Usage

### Encryption/Decryption
```c++
unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
unsigned char key[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char iv[]    = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

AES aes(AESKeyLength::AES_128);
auto cipher   = aes.EncryptCBC(plain, sizeof(plain), key, iv);
auto restored = aes.DecryptCBC(cipher.get(), sizeof(plain), key, iv);
```

### GCM Tagging
GCM mode requires a 12-byte (96-bit) IV.
```c++
unsigned char gcm_iv[12] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                             0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
unsigned char tag[16];
AES aesGcm(AESKeyLength::AES_128);
auto cipherGcm =
    aesGcm.EncryptGCM(plain, sizeof(plain), key, gcm_iv, tag);
// 'tag' now contains the authentication tag for the ciphertext
```




# Padding
This library does not provide any padding because padding is not part of AES standard. Plaintext and ciphertext length in bytes must be divisible by 16. If length doesn't satisfy this condition exception will be thrown


# Links


* [Wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [NIST](https://www.nist.gov/publications/advanced-encryption-standard-aes)

# Development:

1. `git clone https://github.com/SergeyBel/AES.git`
1. `docker-compose up -d`
1. use make commands

There are four executables in `bin` folder:  
* `test` - run tests  
* `debug` - version for debugging (main code will be taken from dev/main.cpp)  
* `profile` - version for profiling with gprof (main code will be taken from dev/main.cpp)  
* `speedtest` - performance speed test (main code will be taken from speedtest/main.cpp)
* `release` - version with optimization (main code will be taken from dev/main.cpp)  


Build commands:  
* `make build_all` - build all targets
* `make build_test` - build `test` target
* `make build_debug` - build `debug` target
* `make build_profile` - build `profile` target
* `make build_speed_test` - build `speedtest` target
* `make build_release` - build `release` target
* `make style_fix` - fix code style
* `make test` - run tests
* `make debug` - run debug version
* `make profile` - run profile version
* `make speed_test` - run performance speed test
* `make release` - run `release` version
* `make clean` - clean `bin` directory

To enable project hooks run:
`git config core.hooksPath .githooks`
