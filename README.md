#AES
C++ AES(Advanced Encryption Standard) implementation

Forked from [SergeyBel/AES](https://github.com/SergeyBel/AES).

[![Ubuntu](https://github.com/NewYaroslav/AES/actions/workflows/aes-ci.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/AES/actions/workflows/aes-ci.yml)
[![Windows](https://github.com/NewYaroslav/AES/actions/workflows/aes-ci-windows.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/AES/actions/workflows/aes-ci-windows.yml)

## Prerequisites
* C++ compiler
* CMake 2.8 or newer

## Hardware Acceleration
On x86 CPUs this library checks for AES-NI support at runtime and uses
hardware-accelerated instructions when available. If AES-NI is missing, a
portable software implementation is used instead.

## Supported Modes
ECB, CBC, CFB, CTR and GCM modes are implemented. GCM additionally produces an authentication tag for message integrity.
ECB mode is provided for completeness but leaks plaintext patterns and should be avoided. Prefer authenticated encryption modes such as GCM that provide both confidentiality and integrity.

## IV Generation
`aescpp::utils` provides helpers for creating random IVs. `generate_iv_16()`
produces a 16-byte IV for CBC, CFB and CTR modes, while `generate_iv_12()`
returns a 12-byte IV recommended for GCM.

## Vector Overloads
All encryption and decryption methods have overloads that accept `std::vector<unsigned char>` in addition to raw pointer APIs:
```c++
#include <aescpp/aes.hpp>

std::vector<unsigned char> plainVec = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
std::vector<unsigned char> keyVec   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char iv[]                  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

AES aesVec(AESKeyLength::AES_128);
auto cipherVec = aesVec.EncryptCBC(plainVec, keyVec, iv);
```

## Usage

### Encryption/Decryption
```c++
#include <aescpp/aes.hpp>

unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
unsigned char key[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char iv[]    = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

AES aes(AESKeyLength::AES_128);
auto cipher   = aes.EncryptCBC(plain, sizeof(plain), key, iv);
auto restored = aes.DecryptCBC(cipher.get(), sizeof(plain), key, iv);
```

### encrypt/decrypt with `AesMode::CTR`
```c++
#include <aescpp/aes_utils.hpp>

using namespace aescpp;

std::string text = "CTR mode example";
std::array<uint8_t, 16> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR);
auto restored =
    utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR);
```

### HMAC Callback
`utils::encrypt`, `utils::decrypt`, and `utils::decrypt_to_string` for CBC, CFB
and CTR modes accept an optional callback for computing a message
authentication code over the IV and ciphertext. Use the same callback for both
operations to detect tampering before returning plaintext.

```c++
auto hmac_fn = [](const std::vector<uint8_t> &iv,
                  const std::vector<uint8_t> &ct) {
  return my_hmac(iv, ct); // user-provided implementation
};

auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR, hmac_fn);
auto restored =
    utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR, hmac_fn);
```

### GCM Helpers
`encrypt_gcm` and `decrypt_gcm` manage the 12-byte IV, optional additional
authenticated data (AAD), and the authentication tag produced by GCM.

GCM limits AAD to `(1ULL << 39) - 256` bytes and the combined length of AAD and
plaintext to the same bound. The library throws `std::length_error` if these
limits are exceeded:
```c++
#include <aescpp/aes_utils.hpp>

using namespace aescpp;

std::string text = "GCM example";
std::array<uint8_t, 16> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
std::vector<uint8_t> aad = { 'h', 'e', 'a', 'd', 'e', 'r' };
auto data = utils::encrypt_gcm(text, key, aad);
// data.tag holds the 16-byte authentication tag
auto plain = utils::decrypt_gcm_to_string(data, key, aad);
```

#Padding
This library does not provide any padding because padding is not part of AES standard.
For ECB and CBC modes plaintext and ciphertext length in bytes must be divisible by
16. CFB, CTR and GCM modes operate on data of any length. If the length for ECB or
CBC doesn't satisfy this condition an exception will be thrown

#Links


* [Wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [NIST](https://www.nist.gov/publications/advanced-encryption-standard-aes)

#Development:

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
