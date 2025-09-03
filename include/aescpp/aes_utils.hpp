#ifndef __AESCPP_AES_UTILS_HPP_
#define __AESCPP_AES_UTILS_HPP_

#include <aescpp/aes.hpp>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace aescpp {

namespace utils {
/// \brief AES block size in bytes.
constexpr std::size_t BLOCK_SIZE = 16;

namespace detail {
/// \brief Fill buffer with random bytes from the operating system.
/// \param data Destination buffer.
/// \param len Number of bytes to generate.
/// \return True on success.
bool fill_os_random(void *data, size_t len) noexcept;

}  // namespace detail

/// \brief Generate a random 12-byte IV.
/// \return Array containing the IV.
std::array<uint8_t, 12> generate_iv_12();

/// \brief Generate a random 16-byte IV.
/// \return Array containing the IV.
std::array<uint8_t, 16> generate_iv_16();

/// \brief Add PKCS#7 padding to data.
/// \param data Input data.
/// \return Padded data.
std::vector<uint8_t> add_padding(const std::vector<uint8_t> &data);

/// \brief Remove PKCS#7 padding from data.
/// \param data Padded data.
/// \param out Receives data with padding removed.
/// \return True if padding is valid.
bool remove_padding(const std::vector<uint8_t> &data,
                    std::vector<uint8_t> &out) noexcept;

/// \brief Prepend IV to ciphertext.
/// \param ciphertext Ciphertext without IV.
/// \param iv Initialization vector to prepend.
/// \return Combined buffer with IV followed by ciphertext.
std::vector<uint8_t> add_iv_to_ciphertext(
    const std::vector<uint8_t> &ciphertext,
    const std::array<uint8_t, BLOCK_SIZE> &iv);

/// \brief Extract IV from ciphertext buffer.
/// \param ciphertext_with_iv Buffer containing IV followed by ciphertext.
/// \param iv Receives extracted IV.
/// \return Ciphertext without IV.
std::vector<uint8_t> extract_iv_from_ciphertext(
    const std::vector<uint8_t> &ciphertext_with_iv,
    std::array<uint8_t, BLOCK_SIZE> &iv);

/// \brief Container for encrypted data with IV and timestamp.
struct EncryptedData {
  std::chrono::system_clock::time_point timestamp;  ///< Creation time.
  std::array<uint8_t, BLOCK_SIZE> iv;               ///< Initialization vector.
  std::vector<uint8_t> ciphertext;                  ///< Ciphertext bytes.
  std::vector<uint8_t> hmac;                        ///< Optional HMAC.
};

/// \brief Container for GCM encrypted data with authentication tag.
struct GcmEncryptedData {
  std::chrono::system_clock::time_point timestamp;  ///< Creation time.
  std::array<uint8_t, 12> iv;                       ///< 12-byte IV.
  std::vector<uint8_t> ciphertext;                  ///< Ciphertext bytes.
  std::array<uint8_t, 16> tag;                      ///< 16-byte auth tag.
};

/// \brief Modes supported by legacy helpers.
enum class AesMode { CBC, CFB, CTR };

/// \brief Callback to compute an HMAC over IV and ciphertext.
using HmacFn = std::function<std::vector<uint8_t>(
    const std::array<uint8_t, BLOCK_SIZE> &iv,
    const std::vector<uint8_t> &ciphertext)>;

/// \brief Determine AES key length from key container size.
/// \tparam T Key type providing `size()`.
/// \param key Key data.
/// \return Corresponding AES key length.
template <class T>
AESKeyLength key_length_from_key(const T &key);

/// \brief Encrypt data using the specified block mode.
/// \tparam T Container type holding the key.
/// \param plain Plaintext bytes.
/// \param key Key material.
/// \param mode Block mode to use.
/// \return Encrypted data with IV and timestamp.
template <class T>
EncryptedData encrypt(const std::vector<uint8_t> &plain, const T &key,
                      AesMode mode, const HmacFn &hmac_fn = {});

/// \brief Encrypt string data using the specified block mode.
/// \tparam T Container type holding the key.
/// \param plain_text Input string.
/// \param key Key material.
/// \param mode Block mode to use.
/// \return Encrypted data with IV and timestamp.
template <class T>
EncryptedData encrypt(const std::string &plain_text, const T &key, AesMode mode,
                      const HmacFn &hmac_fn = {});

/// \brief Decrypt previously encrypted data.
/// \tparam T Container type holding the key.
/// \param data Encrypted container.
/// \param key Key material.
/// \param mode Block mode used during encryption.
/// \return Decrypted bytes.
template <class T>
std::vector<uint8_t> decrypt(const EncryptedData &data, const T &key,
                             AesMode mode, const HmacFn &hmac_fn = {});

/// \brief Decrypt data and return as string.
/// \tparam T Container type holding the key.
/// \param data Encrypted container.
/// \param key Key material.
/// \param mode Block mode used during encryption.
/// \return Decrypted text.
template <class T>
std::string decrypt_to_string(const EncryptedData &data, const T &key,
                              AesMode mode, const HmacFn &hmac_fn = {});

/// \brief Encrypt data using AES-GCM.
/// \tparam T Container type holding the key.
/// \param plain Plaintext bytes.
/// \param key Key material.
/// \param aad Additional authenticated data; may be empty.
/// \return Encrypted data with IV, ciphertext and tag.
template <class T>
GcmEncryptedData encrypt_gcm(const std::vector<uint8_t> &plain, const T &key,
                             const std::vector<uint8_t> &aad = {});

/// \brief Encrypt string data using AES-GCM.
/// \tparam T Container type holding the key.
/// \param plain_text Input string.
/// \param key Key material.
/// \param aad Additional authenticated data; may be empty.
/// \return Encrypted data with IV, ciphertext and tag.
template <class T>
GcmEncryptedData encrypt_gcm(const std::string &plain_text, const T &key,
                             const std::vector<uint8_t> &aad = {});

/// \brief Decrypt AES-GCM encrypted data.
/// \tparam T Container type holding the key.
/// \param data Encrypted container.
/// \param key Key material.
/// \param aad Additional authenticated data used during encryption.
/// \return Decrypted bytes.
/// \throws std::runtime_error If authentication fails.
template <class T>
std::vector<uint8_t> decrypt_gcm(const GcmEncryptedData &data, const T &key,
                                 const std::vector<uint8_t> &aad = {});

/// \brief Decrypt AES-GCM encrypted data and return as string.
/// \tparam T Container type holding the key.
/// \param data Encrypted container.
/// \param key Key material.
/// \param aad Additional authenticated data used during encryption.
/// \return Decrypted text.
/// \throws std::runtime_error If authentication fails.
template <class T>
std::string decrypt_gcm_to_string(const GcmEncryptedData &data, const T &key,
                                  const std::vector<uint8_t> &aad = {});

}  // namespace utils

}  // namespace aescpp

#endif  // __AESCPP_AES_UTILS_HPP_
