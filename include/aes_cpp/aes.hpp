#ifndef __AESCPP_AES_HPP_
#define __AESCPP_AES_HPP_

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#if __cplusplus >= 201703L
#include <shared_mutex>
using AESCPP_SHARED_MUTEX = std::shared_mutex;
template <class M>
using AESCPP_SHARED_LOCK = std::shared_lock<M>;
#else
#include <mutex>
using AESCPP_SHARED_MUTEX = std::mutex;
template <class M>
using AESCPP_SHARED_LOCK = std::unique_lock<M>;
#endif
#include <stdexcept>
#include <string>
#include <vector>

#if __cplusplus >= 201703L
#define AESCPP_NODISCARD [[nodiscard]]
#else
#define AESCPP_NODISCARD
#endif

#if __cplusplus >= 201402L
#define AESCPP_MAKE_UNIQUE(T, n) std::make_unique<T[]>(n)
#else
#define AESCPP_MAKE_UNIQUE(T, n) std::unique_ptr<T[]>(new T[n])
#endif

#if __cplusplus >= 201402L
#define AESCPP_DEPRECATED(msg) [[deprecated(msg)]]
#else
#define AESCPP_DEPRECATED(msg)
#endif

namespace aes_cpp {

/// \brief Overwrite a memory region with zeros.
/// \param p Pointer to the memory block to clear.
/// \param n Size of the block in bytes.
void secure_zero(void *p, size_t n);

/// \brief Supported AES key lengths.
enum class AESKeyLength { AES_128, AES_192, AES_256 };

/// \brief AES cipher implementation with multiple block modes.
///
/// Example usage:
/// \code
/// aes_cpp::AES aes(aes_cpp::AESKeyLength::AES_128);
/// auto cipher = aes.EncryptECB(plain, sizeof(plain), key);
/// \endcode
class AES {
 public:
  /// \brief Construct an AES object.
  /// \param keyLength Desired key length variant.
  explicit AES(const AESKeyLength keyLength = AESKeyLength::AES_256);

  /// \brief Destroy the AES object and securely clear cached keys.
  ~AES();

  /// \brief Securely erase cached key material.
  /// \note Call after sensitive operations to remove residual keys. The
  ///       destructor invokes this automatically.
  void clear_cache();

  /// \brief Encrypt data using ECB mode.
  /// \warning ECB mode leaks plaintext patterns and should not be used for new
  ///          code. Prefer an authenticated mode like GCM.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; must be divisible by 16.
  /// \param key Encryption key.
  /// \return Newly allocated ciphertext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD AESCPP_DEPRECATED(
      "ECB mode leaks plaintext patterns; use an authenticated mode like "
      "GCM") unsigned char *EncryptECB(const unsigned char in[], size_t inLen,
                                       const unsigned char key[]);

  /// \brief Decrypt data previously encrypted with ECB mode.
  /// \warning ECB mode leaks plaintext patterns and should not be used for new
  ///          code. Prefer an authenticated mode like GCM.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; must be divisible by 16.
  /// \param key Decryption key.
  /// \return Newly allocated plaintext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD AESCPP_DEPRECATED(
      "ECB mode leaks plaintext patterns; use an authenticated mode like "
      "GCM") unsigned char *DecryptECB(const unsigned char in[], size_t inLen,
                                       const unsigned char key[]);

  /// \brief Encrypt data using CBC mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; must be divisible by 16.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \return Newly allocated ciphertext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD unsigned char *EncryptCBC(const unsigned char in[],
                                             size_t inLen,
                                             const unsigned char key[],
                                             const unsigned char *iv);

  /// \brief Decrypt data encrypted with CBC mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; must be divisible by 16.
  /// \param key Decryption key.
  /// \param iv Initialization vector used for encryption (16 bytes).
  /// \return Newly allocated plaintext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD unsigned char *DecryptCBC(const unsigned char in[],
                                             size_t inLen,
                                             const unsigned char key[],
                                             const unsigned char *iv);

  /// \brief Encrypt data using CFB mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; may be any value.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \return Newly allocated ciphertext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD unsigned char *EncryptCFB(const unsigned char in[],
                                             size_t inLen,
                                             const unsigned char key[],
                                             const unsigned char *iv);

  /// \brief Decrypt data encrypted with CFB mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; may be any value.
  /// \param key Decryption key.
  /// \param iv Initialization vector used for encryption (16 bytes).
  /// \return Newly allocated plaintext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD unsigned char *DecryptCFB(const unsigned char in[],
                                             size_t inLen,
                                             const unsigned char key[],
                                             const unsigned char *iv);

  /// \brief Encrypt data using CTR mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; may be any value.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \return Newly allocated ciphertext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD unsigned char *EncryptCTR(const unsigned char in[],
                                             size_t inLen,
                                             const unsigned char key[],
                                             const unsigned char iv[]);

  /// \brief Decrypt data encrypted with CTR mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; may be any value.
  /// \param key Decryption key.
  /// \param iv Initialization vector used for encryption (16 bytes).
  /// \return Newly allocated plaintext; caller must delete[] using `delete[]`.
  AESCPP_NODISCARD unsigned char *DecryptCTR(const unsigned char in[],
                                             size_t inLen,
                                             const unsigned char key[],
                                             const unsigned char iv[]);

  /// \brief Encrypt data using CBC mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; must be divisible by 16.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \param out Output buffer with space for \p inLen bytes of ciphertext.
  void EncryptCBC(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char *iv,
                  unsigned char out[]);
  /// \brief Decrypt data encrypted with CBC mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; must be divisible by 16.
  /// \param key Decryption key.
  /// \param iv Initialization vector used during encryption (16 bytes).
  /// \param out Output buffer with space for \p inLen bytes of plaintext.
  void DecryptCBC(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char *iv,
                  unsigned char out[]);
  /// \brief Encrypt data using CFB mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; may be any value.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \param out Output buffer with space for \p inLen bytes of ciphertext.
  void EncryptCFB(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char *iv,
                  unsigned char out[]);
  /// \brief Decrypt data encrypted with CFB mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; may be any value.
  /// \param key Decryption key.
  /// \param iv Initialization vector used during encryption (16 bytes).
  /// \param out Output buffer with space for \p inLen bytes of plaintext.
  void DecryptCFB(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char *iv,
                  unsigned char out[]);
  /// \brief Encrypt data using CTR mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes; may be any value.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \param out Output buffer with space for \p inLen bytes of ciphertext.
  void EncryptCTR(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char iv[],
                  unsigned char out[]);
  /// \brief Decrypt data encrypted with CTR mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes; may be any value.
  /// \param key Decryption key.
  /// \param iv Initialization vector used during encryption (16 bytes).
  /// \param out Output buffer with space for \p inLen bytes of plaintext.
  void DecryptCTR(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char iv[],
                  unsigned char out[]);

  /// \brief Encrypt data using GCM mode.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes.
  /// \param key Encryption key.
  /// \param iv 12-byte initialization vector.
  /// \param aad Additional authenticated data, may be nullptr when \p aadLen is
  /// 0.
  /// \param aadLen Length of \p aad in bytes.
  /// \param tag Output buffer for 16-byte authentication tag.
  /// \return Newly allocated ciphertext; caller must delete[] using `delete[]`.
  /// \throws std::length_error If \p inLen exceeds (1ULL << 32) * 16 bytes, if
  /// \p aadLen exceeds (1ULL << 39) - 256 bytes, or if \p aadLen + \p inLen
  /// exceeds (1ULL << 39) - 256 bytes.
  /// \note IV length must be exactly 12 bytes.
  AESCPP_NODISCARD unsigned char *EncryptGCM(
      const unsigned char in[], size_t inLen, const unsigned char key[],
      const unsigned char iv[], const unsigned char aad[], size_t aadLen,
      unsigned char tag[]);

  /// \brief Decrypt data encrypted with GCM mode.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes.
  /// \param key Decryption key.
  /// \param iv 12-byte initialization vector used for encryption.
  /// \param aad Additional authenticated data; may be nullptr when \p aadLen is
  /// 0.
  /// \param aadLen Length of \p aad in bytes.
  /// \param tag Expected 16-byte authentication tag.
  /// \return Newly allocated plaintext; caller must delete[] using `delete[]`.
  /// \throws std::runtime_error If authentication fails.
  /// \throws std::length_error If \p inLen exceeds (1ULL << 32) * 16 bytes, if
  /// \p aadLen exceeds (1ULL << 39) - 256 bytes, or if \p aadLen + \p inLen
  /// exceeds (1ULL << 39) - 256 bytes.
  /// \note IV length must be exactly 12 bytes.
  AESCPP_NODISCARD unsigned char *DecryptGCM(
      const unsigned char in[], size_t inLen, const unsigned char key[],
      const unsigned char iv[], const unsigned char aad[], size_t aadLen,
      const unsigned char tag[]);

  /// \brief Encrypt data in ECB mode.
  /// \param in Input vector.
  /// \param key Encryption key.
  /// \return Ciphertext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> EncryptECB(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> EncryptECB(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key);

  /// \brief Decrypt data encrypted with ECB mode.
  /// \param in Ciphertext vector.
  /// \param key Decryption key.
  /// \return Plaintext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> DecryptECB(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> DecryptECB(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key);

  /// \brief Encrypt data using CBC mode.
  /// \param in Input vector.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \return Ciphertext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> EncryptCBC(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> EncryptCBC(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv);

  /// \brief Decrypt data encrypted with CBC mode.
  /// \param in Ciphertext vector.
  /// \param key Decryption key.
  /// \param iv Initialization vector used for encryption (16 bytes).
  /// \return Plaintext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> DecryptCBC(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> DecryptCBC(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv);

  /// \brief Encrypt data using CFB mode.
  /// \param in Input vector.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \return Ciphertext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> EncryptCFB(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> EncryptCFB(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv);

  /// \brief Decrypt data encrypted with CFB mode.
  /// \param in Ciphertext vector.
  /// \param key Decryption key.
  /// \param iv Initialization vector used for encryption (16 bytes).
  /// \return Plaintext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> DecryptCFB(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> DecryptCFB(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv);

  /// \brief Encrypt data using CTR mode.
  /// \param in Input vector.
  /// \param key Encryption key.
  /// \param iv Initialization vector (16 bytes).
  /// \return Ciphertext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> EncryptCTR(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> EncryptCTR(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv);

  /// \brief Decrypt data encrypted with CTR mode.
  /// \param in Ciphertext vector.
  /// \param key Decryption key.
  /// \param iv Initialization vector used for encryption (16 bytes).
  /// \return Plaintext of the same length as \p in.
  AESCPP_NODISCARD std::vector<unsigned char> DecryptCTR(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> DecryptCTR(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv);

  /// \brief Encrypt data using GCM mode.
  /// \param in Input vector.
  /// \param key Encryption key.
  /// \param iv 12-byte initialization vector.
  /// \param aad Additional authenticated data.
  /// \param tag Output tag resized to 16 bytes.
  /// \return Ciphertext of the same length as \p in.
  /// \throws std::length_error If the input exceeds (1ULL << 32) * 16 bytes, if
  /// \p aad exceeds (1ULL << 39) - 256 bytes, or if the sum of \p aad and \p in
  /// exceeds (1ULL << 39) - 256 bytes.
  /// \note IV must be 12 bytes.
  AESCPP_NODISCARD std::vector<unsigned char> EncryptGCM(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv,
      const std::vector<unsigned char> &aad, std::vector<unsigned char> &tag);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> EncryptGCM(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv, std::vector<unsigned char> &&aad,
      std::vector<unsigned char> &tag);

  /// \brief Decrypt data encrypted with GCM mode.
  /// \param in Ciphertext vector.
  /// \param key Decryption key.
  /// \param iv 12-byte initialization vector used for encryption.
  /// \param aad Additional authenticated data.
  /// \param tag Authentication tag to verify.
  /// \return Plaintext of the same length as \p in.
  /// \throws std::runtime_error If authentication fails.
  /// \throws std::length_error If the input exceeds (1ULL << 32) * 16 bytes, if
  /// \p aad exceeds (1ULL << 39) - 256 bytes, or if the sum of \p aad and \p in
  /// exceeds (1ULL << 39) - 256 bytes.
  /// \note IV must be 12 bytes.
  AESCPP_NODISCARD std::vector<unsigned char> DecryptGCM(
      const std::vector<unsigned char> &in,
      const std::vector<unsigned char> &key,
      const std::vector<unsigned char> &iv,
      const std::vector<unsigned char> &aad,
      const std::vector<unsigned char> &tag);

  /// \overload
  AESCPP_NODISCARD std::vector<unsigned char> DecryptGCM(
      std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
      std::vector<unsigned char> &&iv, std::vector<unsigned char> &&aad,
      std::vector<unsigned char> &&tag);

  /// \brief Encrypt data using GCM mode into a caller-provided buffer.
  /// \param in Input buffer.
  /// \param inLen Length of input in bytes.
  /// \param key Encryption key.
  /// \param iv 12-byte initialization vector.
  /// \param aad Additional authenticated data; may be nullptr when \p aadLen is
  /// 0.
  /// \param aadLen Length of \p aad in bytes.
  /// \param tag Output buffer for the 16-byte authentication tag.
  /// \param out Output buffer with space for \p inLen bytes of ciphertext.
  /// \throws std::length_error If \p inLen exceeds (1ULL << 32) * 16 bytes, if
  /// \p aadLen exceeds (1ULL << 39) - 256 bytes, or if \p aadLen + \p inLen
  /// exceeds (1ULL << 39) - 256 bytes.
  /// \note IV length must be exactly 12 bytes.
  void EncryptGCM(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char iv[],
                  const unsigned char aad[], size_t aadLen, unsigned char tag[],
                  unsigned char out[]);
  /// \brief Decrypt data encrypted with GCM mode into a caller-provided buffer.
  /// \param in Ciphertext buffer.
  /// \param inLen Length of ciphertext in bytes.
  /// \param key Decryption key.
  /// \param iv 12-byte initialization vector used during encryption.
  /// \param aad Additional authenticated data; may be nullptr when \p aadLen is
  /// 0.
  /// \param aadLen Length of \p aad in bytes.
  /// \param tag Expected 16-byte authentication tag.
  /// \param out Output buffer with space for \p inLen bytes of plaintext.
  /// \throws std::runtime_error If authentication fails.
  /// \throws std::length_error If \p inLen exceeds (1ULL << 32) * 16 bytes, if
  /// \p aadLen exceeds (1ULL << 39) - 256 bytes, or if \p aadLen + \p inLen
  /// exceeds (1ULL << 39) - 256 bytes.
  /// \note IV length must be exactly 12 bytes.
  void DecryptGCM(const unsigned char in[], size_t inLen,
                  const unsigned char key[], const unsigned char iv[],
                  const unsigned char aad[], size_t aadLen,
                  const unsigned char tag[], unsigned char out[]);

#ifdef AESCPP_DEBUG
  /// \brief Print byte array as hexadecimal values.
  /// \param a Array to print.
  /// \param n Number of bytes in \p a.
  /// \warning For debugging only; do not use with sensitive data in production.
  void printHexArray(unsigned char a[], size_t n);

  /// \brief Print vector contents as hexadecimal values.
  /// \param a Vector to print.
  /// \warning For debugging only; do not use with sensitive data in production.
  void printHexVector(const std::vector<unsigned char> &a);

  /// \overload
  /// \warning For debugging only; do not use with sensitive data in production.
  void printHexVector(std::vector<unsigned char> &&a);
#endif

 private:
  static constexpr unsigned int Nb = 4;
  static constexpr unsigned int blockBytesLen = 4 * Nb * sizeof(unsigned char);

  unsigned int Nk;
  unsigned int Nr;

  void SubBytes(unsigned char state[4][Nb]);

  /// \brief Shift row \p i by \p n positions.
  /// \param state State matrix to modify.
  /// \param i Row index.
  /// \param n Number of positions to shift.
  void ShiftRow(unsigned char state[4][Nb], unsigned int i, unsigned int n);

  void ShiftRows(unsigned char state[4][Nb]);

  /// \brief Multiply a byte by x in GF(2^8).
  /// \param b Input byte.
  /// \return Result of the multiplication.
  unsigned char xtime(unsigned char b);

  void MixColumns(unsigned char state[4][Nb]);

  void AddRoundKey(unsigned char state[4][Nb], const unsigned char *key);

  void SubWord(unsigned char *a);

  void RotWord(unsigned char *a);

  void XorWords(unsigned char *a, unsigned char *b, unsigned char *c);

  void Rcon(unsigned char *a, unsigned int n);

  void InvSubBytes(unsigned char state[4][Nb]);

  void InvMixColumns(unsigned char state[4][Nb]);

  void InvShiftRows(unsigned char state[4][Nb]);

  void CheckLength(size_t len);

  void KeyExpansion(const unsigned char key[], unsigned char w[]);

  std::shared_ptr<const std::vector<unsigned char>> prepare_round_keys(
      const unsigned char *key);

  void EncryptECB(const unsigned char in[], size_t inLen,
                  const unsigned char key[], unsigned char out[]);
  void DecryptECB(const unsigned char in[], size_t inLen,
                  const unsigned char key[], unsigned char out[]);

  void EncryptBlock(const unsigned char in[], unsigned char out[],
                    const unsigned char *roundKeys);

  void DecryptBlock(const unsigned char in[], unsigned char out[],
                    const unsigned char *roundKeys);

  void XorBlocks(const unsigned char *a, const unsigned char *b,
                 unsigned char *c, size_t len) noexcept;

  void GF_Multiply(const unsigned char *X, const unsigned char *Y,
                   unsigned char *Z);

  // Update GHASH state in `tag` with a single block of `len` bytes from `X`.
  // `len` must be at most 16 and missing bytes are treated as zero.
  void GHASH(const unsigned char *H, const unsigned char *X, size_t len,
             unsigned char *tag);

  // Convert raw array to a std::vector.
  std::vector<unsigned char> ArrayToVector(unsigned char *a, size_t len);

  std::vector<unsigned char> cachedKey;
  std::shared_ptr<std::vector<unsigned char>> cachedRoundKeys;
  AESCPP_SHARED_MUTEX cacheMutex;
};

constexpr std::array<uint8_t, 256> sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

constexpr std::array<uint8_t, 256> inv_sbox = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

/// \brief Circulant MDS matrix.
static const unsigned char CMDS[4][4] = {
    {2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};

/// \brief Inverse circulant MDS matrix.
static const unsigned char INV_CMDS[4][4] = {
    {14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14}};

}  // namespace aes_cpp

namespace asecpp = aes_cpp;

#endif  // __AESCPP_AES_HPP_
