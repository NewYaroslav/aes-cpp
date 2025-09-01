#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

// --- feature-test wrapper for __has_include (C++11-safe) -----------------
#ifndef AESUTILS_HAS_INCLUDE
#if defined(__has_include)
#define AESUTILS_HAS_INCLUDE(x) __has_include(x)
#else
#define AESUTILS_HAS_INCLUDE(x) 0
#endif
#endif

// --- Platform detection (pull headers only when relevant) ------------------
#if defined(_WIN32)
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0600  // Vista+
#endif
#if !defined(WINVER)
#define WINVER _WIN32_WINNT
#endif
#if AESUTILS_HAS_INCLUDE(<bcrypt.h>)
#define AESUTILS_HAVE_BCRYPT 1
#include <bcrypt.h>
#include <windows.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt")
#endif
#endif
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#define AESUTILS_HAVE_ARC4RANDOM 1
#include <stdlib.h>
#elif defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
// clang-format off
#if AESUTILS_HAS_INCLUDE(<sys/random.h>)
#define AESUTILS_HAVE_GETRANDOM 1
#include <sys/random.h>
#endif
// clang-format on
#endif

#include "AES.h"
#include "secure_zero.h"

namespace aesutils {

constexpr std::size_t BLOCK_SIZE = 16;

namespace detail {
bool fill_os_random(void *data, size_t len) noexcept;

}  // namespace detail

#ifdef AESUTILS_TRUST_STD_RANDOM_DEVICE
#include <random>
#endif
#ifdef AESUTILS_ALLOW_WEAK_FALLBACK
#include <chrono>
#include <cstring>
#if !defined(_WIN32)
#include <unistd.h>
#else
#include <processthreadsapi.h>
#endif
#endif

std::array<uint8_t, BLOCK_SIZE> generate_iv();
std::vector<uint8_t> add_padding(const std::vector<uint8_t> &data);
std::vector<uint8_t> remove_padding(const std::vector<uint8_t> &data);
std::vector<uint8_t> add_iv_to_ciphertext(
    const std::vector<uint8_t> &ciphertext,
    const std::array<uint8_t, BLOCK_SIZE> &iv);
std::vector<uint8_t> extract_iv_from_ciphertext(
    const std::vector<uint8_t> &ciphertext_with_iv,
    std::array<uint8_t, BLOCK_SIZE> &iv);

struct EncryptedData {
  std::chrono::system_clock::time_point timestamp;
  std::array<uint8_t, BLOCK_SIZE> iv;
  std::vector<uint8_t> ciphertext;
};

enum class AesMode { CBC, CFB };

template <class T>
AESKeyLength key_length_from_key(const T &key);

template <class T>
EncryptedData encrypt(const std::vector<uint8_t> &plain, const T &key,
                      AesMode mode);

template <class T>
EncryptedData encrypt(const std::string &plain_text, const T &key,
                      AesMode mode);

template <class T>
std::vector<uint8_t> decrypt(const EncryptedData &data, const T &key,
                             AesMode mode);

template <class T>
std::string decrypt_to_string(const EncryptedData &data, const T &key,
                              AesMode mode);

}  // namespace aesutils
