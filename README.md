# aes-cpp

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Building with vcpkg](#building-with-vcpkg)
- [CMake Integration](#cmake-integration)
- [Usage](#usage)
- [Development](#development)

C++ AES(Advanced Encryption Standard) implementation.

## Features

- Supports 128-, 192-, and 256-bit keys
- Implements ECB, CBC, CFB, CTR, and GCM modes
- Uses AES-NI hardware acceleration when available
- Provides vector overloads for `std::vector` inputs
- Includes debug helpers for inspecting intermediate states

Forked from [SergeyBel/AES](https://github.com/SergeyBel/AES).

[![Ubuntu](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci.yml)
[![Windows](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci-windows.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci-windows.yml)

Stable releases are maintained on the `stable` branch and in tagged versions.

## Prerequisites
* C++11 or newer compiler
* CMake 3.14 or newer

## Quick Start

```bash
git clone https://github.com/NewYaroslav/aes-cpp.git
cd aes-cpp
cmake -S . -B build
cmake --build build
```

```c++
#include <aes_cpp/aes_utils.hpp>
#include <array>
#include <string>
#include <iostream>

int main() {
    using namespace aes_cpp;
    std::string text = "Hello AES";
    std::array<uint8_t, 16> key = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                   0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
    auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR);
    auto decrypted = utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR);
    std::cout << decrypted << std::endl;
}
```

```bash
g++ quickstart.cpp -std=c++17 -Iinclude build/libaes_cpp.a -o quickstart
./quickstart
```

## Building with vcpkg

```bash
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install
# Enable tests with the optional feature
./vcpkg/vcpkg install --x-feature=tests
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake -DVCPKG_MANIFEST_FEATURES=tests -DAES_CPP_BUILD_TESTS=ON
cmake --build build
```

## CMake Integration

This library can be added to another CMake project via `add_subdirectory`:

```cmake
add_subdirectory(path/to/aes-cpp)
target_link_libraries(your_app PRIVATE aes_cpp::aes_cpp)
```

Alternatively, install the library and use `find_package`:

```bash
cmake -S . -B build
cmake --install build --prefix /your/install/prefix
```

```cmake
find_package(aes_cpp CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE aes_cpp::aes_cpp)
```

## Hardware Acceleration
On x86 CPUs this library checks for AES-NI support at runtime and uses
hardware-accelerated instructions when available. If AES-NI is missing, a
portable software implementation is used instead.

## Supported Modes
ECB, CBC, CFB, CTR and GCM modes are implemented. GCM additionally produces an authentication tag for message integrity. CBC, CFB and CTR can be paired with a MAC callback (e.g., HMAC) to authenticate `IV || ciphertext`; omitting the callback leaves them vulnerable to tampering.
ECB mode is provided for completeness but leaks plaintext patterns and should be avoided. Prefer authenticated encryption modes such as GCM that provide both confidentiality and integrity.

## IV Generation
`aes_cpp::utils` provides helpers for creating random IVs. `generate_iv_16()`
produces a 16-byte IV for CBC, CFB and CTR modes, while `generate_iv_12()`
returns a 12-byte IV recommended for GCM.

## Vector Overloads
All encryption and decryption methods have overloads that accept `std::vector<unsigned char>` in addition to raw pointer APIs:
```c++
#include <aes_cpp/aes.hpp>

std::vector<unsigned char> plainVec = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
std::vector<unsigned char> keyVec   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char iv[]                  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

AES aesVec(AESKeyLength::AES_128);
auto cipherVec = aesVec.EncryptCBC(plainVec, keyVec, iv);
```

## Clearing Cached Keys
The `AES` class caches the last key and its expanded round keys for reuse.
Call `clear_cache()` when this material is no longer needed to securely erase
it. The destructor invokes this automatically.

## Debug Helpers

Defining the `AESCPP_DEBUG` macro enables helper functions such as `printHexArray` and `printHexVector` for inspecting data. These helpers are for debugging only and must not be used with sensitive data in production builds. The `make build_debug` target defines this macro automatically, or you can compile with `-DAESCPP_DEBUG`.

## Usage

### Encryption/Decryption
```c++
#include <aes_cpp/aes.hpp>

unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
unsigned char key[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char iv[]    = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

AES aes(AESKeyLength::AES_128);
auto cipher   = aes.EncryptCBC(plain, sizeof(plain), key, iv);
auto restored = aes.DecryptCBC(cipher.get(), sizeof(plain), key, iv);
```

### encrypt/decrypt with `AesMode::CTR`
```c++
#include <aes_cpp/aes_utils.hpp>

using namespace aes_cpp;

std::string text = "CTR mode example";
std::array<uint8_t, 16> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR);
auto restored =
    utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR);
```

### MAC Callback
`utils::encrypt`, `utils::decrypt`, and `utils::decrypt_to_string` for CBC, CFB
and CTR modes accept an optional callback for computing a message
authentication code. The library authenticates the concatenation of IV and
ciphertext and passes this buffer to the callback. Use the same callback for
both operations to detect tampering before returning plaintext. The MAC should
use its own secret key rather than reusing the AES key. Omitting the callback
disables authentication and is insecure.

```c++
auto mac_fn = [](const std::vector<uint8_t> &data) {
  return my_hmac(data); // data = IV || ciphertext
};

auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR, mac_fn);
auto restored =
    utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR, mac_fn);
```

### Constant-Time Comparison
`utils::constant_time_equal` compares byte vectors without leaking
information through timing, but it assumes the lengths of both inputs are
public because it checks them and derives a loop bound from the larger size.

### GCM Helpers
`encrypt_gcm` and `decrypt_gcm` manage the 12-byte IV, optional additional
authenticated data (AAD), and the authentication tag produced by GCM.

GCM limits AAD to `(1ULL << 39) - 256` bytes and the combined length of AAD and
plaintext to the same bound. The library throws `std::length_error` if these
limits are exceeded:
```c++
#include <aes_cpp/aes_utils.hpp>

using namespace aes_cpp;

std::string text = "GCM example";
std::array<uint8_t, 16> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
std::vector<uint8_t> aad = { 'h', 'e', 'a', 'd', 'e', 'r' };
auto data = utils::encrypt_gcm(text, key, aad);
// data.tag holds the 16-byte authentication tag
auto plain = utils::decrypt_gcm_to_string(data, key, aad);
```

# Padding

The core `AES` class works on 16-byte blocks and expects callers to supply
already padded data. If the plaintext length for ECB or CBC modes is not a
multiple of 16 bytes, an exception is thrown.

`aes_cpp::utils` provides PKCS#7 helpers for CBC mode:

```c++
std::vector<uint8_t> padded = aes_cpp::utils::add_padding(plain);
...
aes_cpp::utils::remove_padding(decrypted, out);
```

Higher-level helpers apply this padding automatically:

```c++
#include <aes_cpp/aes_utils.hpp>

using namespace aes_cpp;

std::string text = "CBC example";
std::array<uint8_t, 16> key = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
auto encrypted = utils::encrypt(text, key, utils::AesMode::CBC);
auto restored = utils::decrypt_to_string(encrypted, key, utils::AesMode::CBC);
```

CFB, CTR and GCM modes operate on data of any length.

# Links

These projects can be used together with aes_cpp:

* [hmac-cpp](https://github.com/NewYaroslav/hmac-cpp) - HMAC for authentication
* [siphash-hpp](https://github.com/NewYaroslav/siphash-hpp) - header-only SipHash library
* [obfy](https://github.com/NewYaroslav/obfy) - generate license verification code
* [ADVobfuscator](https://github.com/NewYaroslav/ADVobfuscator) - compile-time C++ code obfuscation library
* [Wiki](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [NIST](https://www.nist.gov/publications/advanced-encryption-standard-aes)

# Development:

1. `git clone https://github.com/NewYaroslav/aes-cpp.git`
1. Run `./setup-hooks.sh` to enable the clang-format pre-commit hook enforced by `.clang-format`
1. `docker-compose up -d`
1. use make commands

There are four executables in `bin` folder:  
* `test` - run tests  
* `debug` - version for debugging built with `AESCPP_DEBUG` (main code will be taken from dev/main.cpp)
* `profile` - version for profiling with gprof (main code will be taken from dev/main.cpp)  
* `speedtest` - performance speed test (main code will be taken from speedtest/main.cpp)
* `release` - version with optimization (main code will be taken from dev/main.cpp)  


Build commands:

Tests are disabled by default. Run CMake with `-DAES_CPP_BUILD_TESTS=ON` to build them.

* `make build_all` - build all targets
* `make build_test` - build `test` target
* `make build_debug` - build `debug` target (defines `AESCPP_DEBUG`)
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

## Windows Build

Required tools:

* Microsoft Visual C++ (MSVC)
* CMake
* vcpkg

Example commands for Windows PowerShell or Command Prompt:

```powershell
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat
.\vcpkg\vcpkg install --x-feature=tests
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=.\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_MANIFEST_FEATURES=tests -DAES_CPP_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release
```


