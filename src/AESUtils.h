#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include "AES.h"

namespace aesutils {

constexpr std::size_t BLOCK_SIZE = 16;

inline std::array<uint8_t, BLOCK_SIZE> generate_iv() {
  std::array<uint8_t, BLOCK_SIZE> iv{};
  auto seed = static_cast<uint32_t>(
      std::chrono::steady_clock::now().time_since_epoch().count());
  std::mt19937 generator(seed);
  std::uniform_int_distribution<int> distribution(0, 255);
  for (auto &byte : iv) {
    byte = static_cast<uint8_t>(distribution(generator));
  }
  return iv;
}

inline std::vector<uint8_t> add_padding(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> padded = data;
  std::size_t padding = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
  padded.insert(padded.end(), padding, static_cast<uint8_t>(padding));
  return padded;
}

inline std::vector<uint8_t> remove_padding(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    throw std::invalid_argument("Data is empty, cannot remove padding.");
  }
  uint8_t padding = data.back();
  if (padding == 0 || padding > BLOCK_SIZE || padding > data.size()) {
    throw std::invalid_argument("Invalid padding size.");
  }
  for (std::size_t i = data.size() - padding; i < data.size(); ++i) {
    if (data[i] != padding) {
      throw std::invalid_argument("Invalid padding detected.");
    }
  }
  return std::vector<uint8_t>(data.begin(), data.end() - padding);
}

inline std::vector<uint8_t> add_iv_to_ciphertext(
    const std::vector<uint8_t> &ciphertext,
    const std::array<uint8_t, BLOCK_SIZE> &iv) {
  std::vector<uint8_t> result;
  result.reserve(iv.size() + ciphertext.size());
  result.insert(result.end(), iv.begin(), iv.end());
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());
  return result;
}

inline std::vector<uint8_t> extract_iv_from_ciphertext(
    const std::vector<uint8_t> &ciphertext_with_iv,
    std::array<uint8_t, BLOCK_SIZE> &iv) {
  if (ciphertext_with_iv.size() < BLOCK_SIZE) {
    throw std::invalid_argument(
        "Ciphertext is too short to contain a valid IV.");
  }
  std::copy_n(ciphertext_with_iv.begin(), BLOCK_SIZE, iv.begin());
  return std::vector<uint8_t>(ciphertext_with_iv.begin() + BLOCK_SIZE,
                              ciphertext_with_iv.end());
}

struct EncryptedData {
  std::chrono::system_clock::time_point timestamp;
  std::array<uint8_t, BLOCK_SIZE> iv;
  std::vector<uint8_t> ciphertext;
};

enum class AesMode { CBC, CFB };

template <class T>
AESKeyLength key_length_from_key(const T &key) {
  switch (key.size()) {
    case 16:
      return AESKeyLength::AES_128;
    case 24:
      return AESKeyLength::AES_192;
    case 32:
      return AESKeyLength::AES_256;
    default:
      throw std::invalid_argument("Invalid key length");
  }
}

template <class T>
EncryptedData encrypt(const std::vector<uint8_t> &plain, const T &key,
                      AesMode mode) {
  AES aes(key_length_from_key(key));
  auto iv = generate_iv();
  std::vector<uint8_t> padded = add_padding(plain);

  unsigned char *encrypted = nullptr;
  switch (mode) {
    case AesMode::CBC:
      encrypted =
          aes.EncryptCBC(padded.data(), padded.size(), key.data(), iv.data());
      break;
    case AesMode::CFB:
      encrypted =
          aes.EncryptCFB(padded.data(), padded.size(), key.data(), iv.data());
      break;
    default:
      throw std::invalid_argument("Invalid AES mode");
  }

  std::vector<uint8_t> ciphertext(encrypted, encrypted + padded.size());
  explicit_bzero(encrypted, padded.size());
  delete[] encrypted;
  return {std::chrono::system_clock::now(), iv, std::move(ciphertext)};
}

template <class T>
EncryptedData encrypt(const std::string &plain_text, const T &key,
                      AesMode mode) {
  return encrypt(std::vector<uint8_t>(plain_text.begin(), plain_text.end()),
                 key, mode);
}

template <class T>
std::vector<uint8_t> decrypt(const EncryptedData &data, const T &key,
                             AesMode mode) {
  AES aes(key_length_from_key(key));
  unsigned char *decrypted = nullptr;
  switch (mode) {
    case AesMode::CBC:
      decrypted = aes.DecryptCBC(data.ciphertext.data(), data.ciphertext.size(),
                                 key.data(), data.iv.data());
      break;
    case AesMode::CFB:
      decrypted = aes.DecryptCFB(data.ciphertext.data(), data.ciphertext.size(),
                                 key.data(), data.iv.data());
      break;
    default:
      throw std::invalid_argument("Invalid AES mode");
  }

  std::vector<uint8_t> plain(decrypted, decrypted + data.ciphertext.size());
  explicit_bzero(decrypted, data.ciphertext.size());
  delete[] decrypted;
  return remove_padding(plain);
}

template <class T>
std::string decrypt_to_string(const EncryptedData &data, const T &key,
                              AesMode mode) {
  std::vector<uint8_t> plain = decrypt(data, key, mode);
  return std::string(plain.begin(), plain.end());
}

}  // namespace aesutils
