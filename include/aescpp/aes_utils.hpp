#pragma once

#include <aescpp/aes.hpp>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace aescpp {

namespace utils {

constexpr std::size_t BLOCK_SIZE = 16;

namespace detail {
bool fill_os_random(void *data, size_t len) noexcept;

}  // namespace detail

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

}  // namespace utils

}  // namespace aescpp
