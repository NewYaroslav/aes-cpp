# aes-cpp

C++ AES (Advanced Encryption Standard) library.
Forked from [SergeyBel/AES](https://github.com/SergeyBel/AES) and extended with utilities, examples, CMake packaging, and CI.

[![Ubuntu](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci.yml)
[![Windows](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci-windows.yml/badge.svg?branch=main)](https://github.com/NewYaroslav/aes-cpp/actions/workflows/aes-ci-windows.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Stable releases are maintained on the `stable` branch and published as semver tags.

---

* [Features](#features)
* [Security Notes (READ FIRST)](#security-notes-read-first)
* [Requirements](#requirements)
* [Quick Start](#quick-start)
* [CMake Integration](#cmake-integration)

  * [add\_subdirectory](#add_subdirectory)
  * [Installed package (find\_package)](#installed-package-find_package)
  * [Install layout & exported targets](#install-layout--exported-targets)
* [Building with vcpkg](#building-with-vcpkg)
* [Usage](#usage)

  * [CBC example (with padding)](#cbc-example-with-padding)
  * [CTR example (string helpers)](#ctr-example-string-helpers)
  * [GCM example (AEAD) + serialization](#gcm-example-aead--serialization)
  * [MAC callback for CBC/CFB/CTR](#mac-callback-for-cbc-cfb-ctr)
* [IV / Nonce Generation](#iv--nonce-generation)
* [Padding](#padding)
* [Vector Overloads](#vector-overloads)
* [Constant-Time Helpers](#constant-time-helpers)
* [Hardware Acceleration](#hardware-acceleration)
* [Windows Build](#windows-build)
* [Development](#development)
* [FAQ / Troubleshooting](#faq--troubleshooting)
* [Links](#links)
* [License](#license)

---

## Features

* AES-128 / AES-192 / AES-256
* Modes: **ECB**, **CBC**, **CFB**, **CTR**, **GCM**
* Runtime AES-NI detection on x86/x86\_64; software fallback otherwise
* Convenience utilities (`aes_cpp::utils`) with string/`std::vector` helpers
* Optional debug helpers (hex printers) behind `AESCPP_DEBUG`
* CMake package: `aes_cpp::aes_cpp` target, `find_package` support

## Security Notes (READ FIRST)

* **Key management**: the library does **not** generate or store keys. Derive keys via a KDF (PBKDF2/scrypt/Argon2) and manage rotation/storage in your application.
* **Side channels**:

  * Software path is **not constant-time**. Even with AES-NI, side channels may remain depending on platform and usage. Evaluate your threat model (shared CPU, co-tenancy, etc.).
* **IV/nonce uniqueness is mandatory per key**:

  * **GCM (recommended)**: 12-byte IV; **never reuse** an IV with the same key. Reuse breaks confidentiality and integrity.
  * **CTR/CFB**: IV/nonce must be **unique** per key. A counter-based scheme is typical.
  * **CBC**: IV must be **unpredictable** (CSPRNG).
* **ECB** is provided for demonstration only. Do **not** use in real systems; it leaks patterns. Prefer authenticated encryption (GCM).
* **Zeroization**: memory wiping is best-effort and does not cover OS swap or external copies.
  
## Requirements

* C++11 or newer
* CMake ≥ 3.14

## Quick Start

```bash
git clone https://github.com/NewYaroslav/aes-cpp.git
cd aes-cpp
./setup-hooks.sh               # enables clang-format pre-commit (enforced by CI)
cmake -S . -B build
cmake --build build

# enable and run tests
cmake -S . -B build -DAES_CPP_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

Minimal compile & run (Linux, from repo root):

```bash
# Build static lib first via CMake as above, then:
g++ examples/ctr.cpp -std=c++17 -Iinclude -Lbuild -laes_cpp -o ctr_example
./ctr_example
```

## CMake Integration

### add\_subdirectory

```cmake
# CMakeLists.txt
add_subdirectory(external/aes-cpp)
# Optionally: set(AES_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)

target_link_libraries(your_app PRIVATE aes_cpp::aes_cpp)
```

### Installed package (find\_package)

Install to a prefix and consume via `find_package`:

```bash
cmake -S . -B build
cmake --install build --prefix /your/install/prefix
```

```cmake
# consumer CMakeLists.txt
find_package(aes_cpp CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE aes_cpp::aes_cpp)
```

### Install layout & exported targets

The project installs:

* headers → `include/`
* library → `lib/`
* CMake package files → `lib/cmake/aes_cpp/`

  * `aes_cppConfig.cmake`
  * `aes_cppConfigVersion.cmake`
  * `aes_cppTargets.cmake`

Exported target name: **`aes_cpp::aes_cpp`** (also local alias `aescpp`).

## Building with vcpkg

With a vcpkg manifest (`vcpkg.json`) in the repo, typical flow:

```bash
git clone https://github.com/microsoft/vcpkg.git
./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install                 # default triplet
./vcpkg/vcpkg install --x-feature=tests
cmake -S . -B build \
  -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_MANIFEST_FEATURES=tests \
  -DAES_CPP_BUILD_TESTS=ON
cmake --build build
```

On Windows (PowerShell / cmd) see [Windows Build](#windows-build).

## Usage

Include headers from `include/aes_cpp`.

### CBC example (with padding)

```cpp
#include <aes_cpp/aes.hpp>
#include <aes_cpp/aes_utils.hpp>
#include <array>
#include <vector>

using namespace aes_cpp;

int main() {
    const unsigned char plain[] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const unsigned char key[] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    auto iv = utils::generate_iv_16(); // CBC IV from CSPRNG

    AES aes(AESKeyLength::AES_128);
    // utils::encrypt/decrypt auto-apply PKCS#7 for CBC
    auto enc = utils::encrypt(std::vector<uint8_t>(plain, plain+sizeof(plain)), key, utils::AesMode::CBC, std::nullopt, iv);
    auto dec = utils::decrypt(enc, key, utils::AesMode::CBC);
}
```

### CTR example (string helpers)

```cpp
#include <aes_cpp/aes_utils.hpp>
#include <array>
#include <string>
#include <iostream>

using namespace aes_cpp;

int main() {
    std::string text = "CTR mode example";
    std::array<uint8_t,16> key { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    auto iv = utils::generate_iv_16(); // unique per (key, message)

    auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR, std::nullopt, iv);
    auto restored   = utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR, std::nullopt);
    std::cout << restored << "\n";
}
```

**Note (CTR):** throws `std::length_error` on 128-bit counter wrap-around (practically unreachable).

### GCM example (AEAD) + serialization

```cpp
#include <aes_cpp/aes_utils.hpp>
#include <array>
#include <vector>

using namespace aes_cpp;

struct GcmPacket {
    std::array<uint8_t,12> iv;           // 12-byte IV (nonce)
    std::vector<uint8_t>   ciphertext;   // raw bytes
    std::array<uint8_t,16> tag;          // 16-byte auth tag
};

int main() {
    std::string text = "GCM example";
    std::array<uint8_t,16> key { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    std::vector<uint8_t> aad = { 'h','e','a','d','e','r' };

    auto enc = utils::encrypt_gcm(text, key, aad); // produces {iv, ciphertext, tag}

    // Serialize as {iv || ciphertext || tag} if desired
    std::vector<uint8_t> wire;
    wire.insert(wire.end(), enc.iv.begin(), enc.iv.end());
    wire.insert(wire.end(), enc.ciphertext.begin(), enc.ciphertext.end());
    wire.insert(wire.end(), enc.tag.begin(), enc.tag.end());

    // Decrypt
    auto plain = utils::decrypt_gcm_to_string(enc, key, aad);
}
```

**GCM limits & tag.** AAD ≤ 2^39−256 bytes; AAD+plaintext ≤ 2^39−256 (per spec). 
Implementation limit: plaintext ≤ 2^36 bytes per (key, IV) due to 32-bit block counter.
Tag length is fixed to 16 bytes. On authentication failure the output is zeroized and an exception is thrown (see *Errors & Exceptions*).

### MAC callback for CBC/CFB/CTR

`utils::encrypt`, `utils::decrypt`, and `utils::decrypt_to_string` for CBC/CFB/CTR accept an optional MAC callback. The library authenticates `IV || ciphertext` and passes this buffer to your callback. Use a dedicated MAC key; do **not** reuse the AES key.

```cpp
auto mac_fn = [](const std::vector<uint8_t>& data) {
    return my_hmac(data); // data = IV || ciphertext
};

auto encrypted = utils::encrypt(text, key, utils::AesMode::CTR, mac_fn);
auto restored  = utils::decrypt_to_string(encrypted, key, utils::AesMode::CTR, mac_fn);
```

## IV / Nonce Generation

Utilities in `aes_cpp::utils`:

* `generate_iv_16()` → 16-byte IV for CBC/CFB/CTR (use CSPRNG or a counter scheme ensuring **uniqueness per key**)
* `generate_iv_12()` → 12-byte IV for GCM (**never reuse** with the same key). Random 96-bit IVs are acceptable for many use-cases; a deterministic counter/nonce scheme eliminates collision risk within one key’s lifetime.
* Use a **CSPRNG** for random IVs.

## Padding

Core `AES` operates on 16-byte blocks and expects callers to supply padded data for ECB/CBC.
If the input size is not a multiple of 16, an exception is thrown. `aes_cpp::utils` provides
PKCS#7 helpers and higher-level CBC helpers that apply padding automatically.

## Vector Overloads

Most APIs provide `std::vector<uint8_t>` overloads. They do **not** copy the input;
they allocate an output vector and write results directly into it (return uses NRVO/move).
For zero-allocation scenarios, use pointer/size APIs with a caller-provided output buffer,
or in-place pointer APIs (same buffer for input/output) where applicable.
Note: `DecryptGCM` normalizes the tag to 16 bytes (may copy/resize the tag).
A span-like API may be added later.

## Constant-Time Helpers

`utils::constant_time_equal(a, b)` compares byte sequences in a way that reduces timing leakage for equal-length inputs. Contract: treat lengths as public; compare lengths in protocol logic, then call the function only when sizes match.

## Hardware Acceleration

* **x86/x86_64**: runtime AES-NI detection; hardware path when available, otherwise software fallback.
* **GHASH** (GCM) uses PCLMULQDQ with SSSE3 shuffles when available.
* **Non-x86 (e.g., ARMv8)**: currently uses software path (no ARM Crypto Extensions yet).

### Build flags for acceleration
* GCC/Clang: pass `-maes -mpclmul -mssse3` to compile AES-NI/PCLMUL code paths (selected at runtime).
* MSVC: intrinsics available by default; CPUID selects the path at runtime.
* Without these flags, the software path is always used.

## Windows Build

Requirements: MSVC, CMake, vcpkg

```powershell
git clone https://github.com/microsoft/vcpkg.git
.\vcpkg\bootstrap-vcpkg.bat
.\vcpkg\vcpkg install --x-feature=tests
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=.\vcpkg\scripts\buildsystems\vcpkg.cmake -DVCPKG_MANIFEST_FEATURES=tests -DAES_CPP_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build -C Release
```

Linking example (MSVC): link against `build\Release\aes_cpp.lib` or consume via `find_package` after `cmake --install`.

## Errors & Exceptions

* `std::invalid_argument`: null key/IV/tag/AAD; invalid IV size (GCM requires 12 bytes); tag size > 16.
* `std::length_error`: ECB/CBC input not multiple of 16; GCM AAD/length bounds; CTR counter overflow.
* `std::runtime_error`: GCM authentication failed (output buffer is zeroized before throwing).

## Thread-safety

`AES` methods are safe for concurrent use per instance (key cache is mutex-protected; per-call state is local).

## Development

* Clone: `git clone https://github.com/NewYaroslav/aes-cpp.git`
* Hooks: `./setup-hooks.sh` enables clang-format pre-commit
* Local GTest (optional): `./dev/install_gtest.sh`
* Docker: `docker-compose up -d`
* Make shortcuts:

  * `make build_all` — build all targets
  * `make build_test` — build tests (`-DAES_CPP_BUILD_TESTS=ON`)
  * `make build_debug` — build `debug` (defines `AESCPP_DEBUG`)
  * `make build_profile` — build `profile`
  * `make build_speed_test` — build `speedtest`
  * `make build_release` — build optimized `release`
  * `make test` — run tests
  * `make debug` / `make profile` / `make speed_test` / `make release` — run respective binaries
  * `make style_fix` — fix code style
  * `make clean` — clean `bin`

Binaries in `bin/`:

* `test` — runs tests
* `debug` — debug build (main from `dev/main.cpp`)
* `profile` — gprof build (main from `dev/main.cpp`)
* `speedtest` — performance test (main from `speedtest/main.cpp`)
* `release` — optimized build (main from `dev/main.cpp`)

## FAQ / Troubleshooting

**Compilers/architectures?** GCC, Clang, MSVC on x86/x86\_64 are covered by CI. Other platforms should work with a compatible C++11 compiler; they currently use the software path.

**No AES-NI?** The library falls back to the portable software implementation; expect lower performance.

**Submodule vs package?** As a submodule use `add_subdirectory`. As an installed package use `find_package(aes_cpp CONFIG REQUIRED)` and link `aes_cpp::aes_cpp`.  
Note: the `aescpp` alias is build-tree only; consumers should use `aes_cpp::aes_cpp`.

**vcpkg triplets?** Set explicitly when needed, e.g. `vcpkg install --triplet x64-windows`.

## Links

* [hmac-cpp](https://github.com/NewYaroslav/hmac-cpp) — HMAC for authentication
* [siphash-hpp](https://github.com/NewYaroslav/siphash-hpp) — header-only SipHash
* [ADVobfuscator](https://github.com/NewYaroslav/ADVobfuscator) — compile-time obfuscation (C++20)
* [obfy](https://github.com/NewYaroslav/obfy) — generate license verification code
* [AES (Wikipedia)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)

## License

MIT — see [LICENSE](LICENSE).
