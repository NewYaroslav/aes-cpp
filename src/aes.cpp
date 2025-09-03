#include <aescpp/aes.hpp>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>

#if defined(__has_include)
#if __has_include(<strings.h>)
#include <strings.h>
#endif
#endif

#if defined(_WIN32)
#include <windows.h>
#endif
#if (defined(__PCLMUL__) || defined(__AES__)) &&                  \
    (defined(__x86_64__) || defined(_M_X64) || defined(__i386) || \
     defined(_M_IX86))
#include <wmmintrin.h>
#endif
#if defined(__SSE2__)
#include <emmintrin.h>
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__has_include)
#if __has_include(<cpuid.h>)
#include <cpuid.h>
#endif
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) ||     \
    defined(_M_IX86) || defined(__aarch64__) || defined(_M_ARM64) || \
    defined(__ARM_FEATURE_UNALIGNED)
// Allow direct uint64_t loads on platforms with relaxed alignment
#define AESCPP_HAS_UNALIGNED_UINT64 1
#else
#define AESCPP_HAS_UNALIGNED_UINT64 0
#endif

namespace aescpp {

void secure_zero(void *p, size_t n) {
#if defined(_WIN32)
  SecureZeroMemory(p, n);
#elif defined(explicit_bzero) || defined(__GLIBC__) || defined(__APPLE__) || \
    defined(__OpenBSD__) || defined(__FreeBSD__)
  explicit_bzero(p, n);
#elif defined(__STDC_LIB_EXT1__)
  memset_s(p, n, 0, n);
#else
  volatile unsigned char *v = static_cast<volatile unsigned char *>(p);
  while (n--) *v++ = 0;
#endif
}

bool constant_time_eq(const unsigned char *a, const unsigned char *b,
                      size_t len) {
  uint32_t diff = 0;
  for (size_t i = 0; i < len; ++i) {
    diff |= static_cast<uint32_t>(a[i] ^ b[i]);
  }
  return ((diff - 1) >> 8) & 1;
}

#if defined(__AES__) && (defined(__x86_64__) || defined(_M_X64) || \
                         defined(__i386) || defined(_M_IX86))
static bool has_aesni() {
#if defined(_MSC_VER)
  int info[4];
  __cpuid(info, 1);
  return (info[2] & (1 << 25)) != 0;
#elif defined(__GNUC__) || defined(__clang__)
#ifdef __get_cpuid
  unsigned int eax, ebx, ecx, edx;
  if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
    return (ecx & bit_AES) != 0;
  }
  return false;
#else
  unsigned int eax, ebx, ecx, edx;
  __asm__ volatile("cpuid"
                   : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                   : "a"(1));
  return (ecx & (1u << 25)) != 0;
#endif
#else
  return false;
#endif
}
#endif

#if defined(__PCLMUL__) && (defined(__x86_64__) || defined(_M_X64) || \
                            defined(__i386) || defined(_M_IX86))
static bool has_pclmul() {
#if defined(_MSC_VER)
  static const bool result = []() {
    int info[4];
    __cpuid(info, 1);
    return (info[2] & (1 << 1)) != 0;
  }();
  return result;
#elif defined(__GNUC__) || defined(__clang__)
#ifdef __get_cpuid
  static const bool result = []() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
      return (ecx & bit_PCLMUL) != 0;
    }
    return false;
  }();
  return result;
#else
  static const bool result = []() {
    unsigned int eax, ebx, ecx, edx;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "a"(1));
    return (ecx & (1u << 1)) != 0;
  }();
  return result;
#endif
#else
  return false;
#endif
}
#endif

static constexpr unsigned char R[16] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x87};  // Polynomial: x^128 + x^7 + x^2 + x + 1

static constexpr uint8_t RCON_TABLE[] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                         0x20, 0x40, 0x80, 0x1B, 0x36,
                                         0x6C, 0xD8, 0xAB, 0x4D, 0x9A};

AES::AES(const AESKeyLength keyLength) {
  switch (keyLength) {
    case AESKeyLength::AES_128:
      this->Nk = 4;
      this->Nr = 10;
      break;

    case AESKeyLength::AES_192:
      this->Nk = 6;
      this->Nr = 12;
      break;

    case AESKeyLength::AES_256:
      this->Nk = 8;
      this->Nr = 14;
      break;
  }
}

AES::~AES() {
  if (cachedRoundKeys) {
    secure_zero(cachedRoundKeys->data(), cachedRoundKeys->size());
  }
  secure_zero(cachedKey.data(), cachedKey.size());
}

std::shared_ptr<const std::vector<unsigned char>> AES::prepare_round_keys(
    const unsigned char *key) {
  const size_t keyLen = 4 * Nk;
  {
    AESCPP_SHARED_LOCK<AESCPP_SHARED_MUTEX> lock(cacheMutex);
    if (cachedKey.size() == keyLen &&
        constant_time_eq(cachedKey.data(), key, keyLen)) {
      return cachedRoundKeys;
    }
  }
  std::unique_lock<AESCPP_SHARED_MUTEX> lock(cacheMutex);
  if (cachedKey.size() != keyLen ||
      !constant_time_eq(cachedKey.data(), key, keyLen)) {
    secure_zero(cachedKey.data(), cachedKey.size());
    cachedKey.assign(key, key + keyLen);
    auto newRoundKeys =
        std::make_shared<std::vector<unsigned char>>(4 * Nb * (Nr + 1));
    KeyExpansion(key, newRoundKeys->data());
    if (cachedRoundKeys) {
      secure_zero(cachedRoundKeys->data(), cachedRoundKeys->size());
    }
    cachedRoundKeys = newRoundKeys;
  }
  return cachedRoundKeys;
}

void AES::EncryptECB(const unsigned char in[], size_t inLen,
                     const unsigned char key[], unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(in + i, out + i, roundKeys->data());
  }
}

AESCPP_NODISCARD unsigned char *AES::EncryptECB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[]) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  EncryptECB(in, inLen, key, out.get());
  return out.release();
}

void AES::DecryptECB(const unsigned char in[], size_t inLen,
                     const unsigned char key[], unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, roundKeys->data());
  }
}

AESCPP_NODISCARD unsigned char *AES::DecryptECB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[]) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  DecryptECB(in, inLen, key, out.get());
  return out.release();
}

void AES::EncryptCBC(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char *iv,
                     unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv) throw std::invalid_argument("Null IV");
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    XorBlocks(block, in + i, block, blockBytesLen);
    EncryptBlock(block, out + i, roundKeys->data());
    memcpy(block, out + i, blockBytesLen);
  }

  secure_zero(block, sizeof(block));
}

AESCPP_NODISCARD unsigned char *AES::EncryptCBC(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  EncryptCBC(in, inLen, key, iv, out.get());
  return out.release();
}

void AES::DecryptCBC(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char *iv,
                     unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv) throw std::invalid_argument("Null IV");
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  unsigned char block[blockBytesLen];
  unsigned char temp[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    memcpy(temp, in + i, blockBytesLen);
    DecryptBlock(in + i, out + i, roundKeys->data());
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, temp, blockBytesLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(temp, sizeof(temp));
}

AESCPP_NODISCARD unsigned char *AES::DecryptCBC(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  DecryptCBC(in, inLen, key, iv, out.get());
  return out.release();
}

void AES::EncryptCFB(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char *iv,
                     unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv) throw std::invalid_argument("Null IV");
  auto roundKeys = prepare_round_keys(key);
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys->data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out + i, blockLen);
    memcpy(block, out + i, blockLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(encryptedBlock, sizeof(encryptedBlock));
}

AESCPP_NODISCARD unsigned char *AES::EncryptCFB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  EncryptCFB(in, inLen, key, iv, out.get());
  return out.release();
}

void AES::DecryptCFB(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char *iv,
                     unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv) throw std::invalid_argument("Null IV");
  auto roundKeys = prepare_round_keys(key);
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  unsigned char temp[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys->data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    memcpy(temp, in + i, blockLen);
    XorBlocks(temp, encryptedBlock, out + i, blockLen);
    memcpy(block, temp, blockLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(encryptedBlock, sizeof(encryptedBlock));
  secure_zero(temp, sizeof(temp));
}

AESCPP_NODISCARD unsigned char *AES::DecryptCFB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  DecryptCFB(in, inLen, key, iv, out.get());
  return out.release();
}

void AES::EncryptCTR(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char iv[],
                     unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv) throw std::invalid_argument("Null IV");
  auto roundKeys = prepare_round_keys(key);
  unsigned char counter[blockBytesLen];
  unsigned char encryptedCounter[blockBytesLen];
  memcpy(counter, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(counter, encryptedCounter, roundKeys->data());

    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedCounter, out + i, blockLen);

    for (int j = blockBytesLen - 1; j >= 0; --j) {
      if (++counter[j] != 0) {
        break;
      }
    }
  }

  secure_zero(counter, sizeof(counter));
  secure_zero(encryptedCounter, sizeof(encryptedCounter));
}

AESCPP_NODISCARD unsigned char *AES::EncryptCTR(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char iv[]) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  EncryptCTR(in, inLen, key, iv, out.get());
  return out.release();
}

void AES::DecryptCTR(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char iv[],
                     unsigned char out[]) {
  EncryptCTR(in, inLen, key, iv, out);
}

AESCPP_NODISCARD unsigned char *AES::DecryptCTR(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char iv[]) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  DecryptCTR(in, inLen, key, iv, out.get());
  return out.release();
}

void AES::EncryptGCM(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char iv[],
                     const unsigned char aad[], size_t aadLen,
                     unsigned char tag[], unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv || (!aad && aadLen > 0) || !tag)
    throw std::invalid_argument("Null IV, AAD or tag");
  if (inLen > (1ULL << 32) * 16) throw std::length_error("Input too long");
  const uint64_t gcmLimit = (1ULL << 39) - 256;
  if (aadLen > gcmLimit) throw std::length_error("AAD too long");
  if (aadLen + inLen > gcmLimit)
    throw std::length_error("AAD + input too long");
  auto roundKeys = prepare_round_keys(key);

  // Compute hash subkey H
  unsigned char H[16] = {0};
  unsigned char zeroBlock[16] = {0};
  EncryptBlock(zeroBlock, H, roundKeys->data());

  // Encrypt data in CTR mode
  unsigned char ctr[16] = {0};
  memcpy(ctr, iv, 12);  // IV is 12 bytes
  ctr[15] = 1;          // Set initial counter value
  unsigned char encryptedCtr[16] = {0};

  // GHASH for AAD without intermediate buffers
  memset(tag, 0, 16);
  for (size_t i = 0; i < aadLen; i += 16) {
    GHASH(H, aad + i, std::min<size_t>(16, aadLen - i), tag);
  }

  for (size_t i = 0; i < inLen; i += 16) {
    // Increment counter - GCM requires incrementing J0 before processing data
    for (int j = 15; j >= 0; --j) {
      if (++ctr[j]) break;
    }
    EncryptBlock(ctr, encryptedCtr, roundKeys->data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out + i, blockLen);
    GHASH(H, out + i, blockLen, tag);
  }

  unsigned char lenBlock[16] = {0};
  uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
  uint64_t lenBits = static_cast<uint64_t>(inLen) * 8;
  for (int i = 0; i < 8; i++)
    lenBlock[i] = static_cast<unsigned char>(aadBits >> (56 - 8 * i));
  for (int i = 0; i < 8; i++)
    lenBlock[8 + i] = static_cast<unsigned char>(lenBits >> (56 - 8 * i));
  GHASH(H, lenBlock, 16, tag);

  unsigned char J0[16] = {0};
  memcpy(J0, iv, 12);
  J0[15] = 1;
  unsigned char S[16] = {0};
  EncryptBlock(J0, S, roundKeys->data());
  for (int i = 0; i < 16; i++) {
    tag[i] ^= S[i];
  }

  secure_zero(lenBlock, sizeof(lenBlock));
  secure_zero(H, sizeof(H));
  secure_zero(zeroBlock, sizeof(zeroBlock));
  secure_zero(ctr, sizeof(ctr));
  secure_zero(encryptedCtr, sizeof(encryptedCtr));
  secure_zero(J0, sizeof(J0));
  secure_zero(S, sizeof(S));
}

AESCPP_NODISCARD unsigned char *AES::EncryptGCM(
    const unsigned char in[], size_t inLen, const unsigned char key[],
    const unsigned char iv[], const unsigned char aad[], size_t aadLen,
    unsigned char tag[]) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  EncryptGCM(in, inLen, key, iv, aad, aadLen, tag, out.get());
  return out.release();
}

void AES::DecryptGCM(const unsigned char in[], size_t inLen,
                     const unsigned char key[], const unsigned char iv[],
                     const unsigned char aad[], size_t aadLen,
                     const unsigned char tag[], unsigned char out[]) {
  if (!key) throw std::invalid_argument("Null key");
  if (!iv || (!aad && aadLen > 0) || !tag)
    throw std::invalid_argument("Null IV, AAD or tag");
  if (inLen > (1ULL << 32) * 16) throw std::length_error("Input too long");
  const uint64_t gcmLimit = (1ULL << 39) - 256;
  if (aadLen > gcmLimit) throw std::length_error("AAD too long");
  if (aadLen + inLen > gcmLimit)
    throw std::length_error("AAD + input too long");
  auto roundKeys = prepare_round_keys(key);

  // Compute hash subkey H
  unsigned char H[16] = {0};
  unsigned char zeroBlock[16] = {0};
  EncryptBlock(zeroBlock, H, roundKeys->data());

  // Decrypt data in CTR mode
  unsigned char ctr[16] = {0};
  memcpy(ctr, iv, 12);
  ctr[15] = 1;  // Set initial counter value
  unsigned char encryptedCtr[16] = {0};

  unsigned char calculatedTag[16] = {0};
  // GHASH for AAD without forming a concatenated buffer
  for (size_t i = 0; i < aadLen; i += 16) {
    GHASH(H, aad + i, std::min<size_t>(16, aadLen - i), calculatedTag);
  }

  for (size_t i = 0; i < inLen; i += 16) {
    // Increment counter - GCM requires incrementing J0 before processing data
    for (int j = 15; j >= 0; --j) {
      if (++ctr[j]) break;
    }
    EncryptBlock(ctr, encryptedCtr, roundKeys->data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    // GHASH must run on the ciphertext before it may be overwritten by
    // XorBlocks when operating in-place.
    GHASH(H, in + i, blockLen, calculatedTag);
    XorBlocks(in + i, encryptedCtr, out + i, blockLen);
  }

  unsigned char lenBlock[16] = {0};
  uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
  uint64_t lenBits = static_cast<uint64_t>(inLen) * 8;
  for (int i = 0; i < 8; i++)
    lenBlock[i] = static_cast<unsigned char>(aadBits >> (56 - 8 * i));
  for (int i = 0; i < 8; i++)
    lenBlock[8 + i] = static_cast<unsigned char>(lenBits >> (56 - 8 * i));
  GHASH(H, lenBlock, 16, calculatedTag);

  unsigned char J0[16] = {0};
  memcpy(J0, iv, 12);
  J0[15] = 1;
  unsigned char S[16] = {0};
  EncryptBlock(J0, S, roundKeys->data());
  for (int i = 0; i < 16; i++) {
    calculatedTag[i] ^= S[i];
  }
  bool tagMatch = constant_time_eq(tag, calculatedTag, 16);

  secure_zero(lenBlock, sizeof(lenBlock));
  secure_zero(H, sizeof(H));
  secure_zero(zeroBlock, sizeof(zeroBlock));
  secure_zero(ctr, sizeof(ctr));
  secure_zero(encryptedCtr, sizeof(encryptedCtr));
  secure_zero(calculatedTag, sizeof(calculatedTag));
  secure_zero(J0, sizeof(J0));
  secure_zero(S, sizeof(S));

  if (!tagMatch) {
    secure_zero(out, inLen);
    throw std::runtime_error("Authentication failed");
  }
}

AESCPP_NODISCARD unsigned char *AES::DecryptGCM(
    const unsigned char in[], size_t inLen, const unsigned char key[],
    const unsigned char iv[], const unsigned char aad[], size_t aadLen,
    const unsigned char tag[]) {
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  DecryptGCM(in, inLen, key, iv, aad, aadLen, tag, out.get());
  return out.release();
}

void AES::CheckLength(size_t len) {
  // ensure input length is a multiple of the block size
  if (len % blockBytesLen != 0) {
    throw std::length_error("Plaintext length must be divisible by " +
                            std::to_string(blockBytesLen));
  }
}

#if defined(__AES__) && (defined(__x86_64__) || defined(_M_X64) || \
                         defined(__i386) || defined(_M_IX86))
static void EncryptBlockAESNI(const unsigned char in[], unsigned char out[],
                              const unsigned char *roundKeys, unsigned int Nr) {
  __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in));
  m = _mm_xor_si128(
      m, _mm_loadu_si128(reinterpret_cast<const __m128i *>(roundKeys)));
  for (unsigned int i = 1; i < Nr; ++i) {
    m = _mm_aesenc_si128(
        m,
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(roundKeys + i * 16)));
  }
  m = _mm_aesenclast_si128(
      m,
      _mm_loadu_si128(reinterpret_cast<const __m128i *>(roundKeys + Nr * 16)));
  _mm_storeu_si128(reinterpret_cast<__m128i *>(out), m);
}

static void DecryptBlockAESNI(const unsigned char in[], unsigned char out[],
                              const unsigned char *roundKeys, unsigned int Nr) {
  __m128i m = _mm_loadu_si128(reinterpret_cast<const __m128i *>(in));
  m = _mm_xor_si128(
      m,
      _mm_loadu_si128(reinterpret_cast<const __m128i *>(roundKeys + Nr * 16)));
  for (unsigned int i = Nr - 1; i > 0; --i) {
    __m128i rk =
        _mm_loadu_si128(reinterpret_cast<const __m128i *>(roundKeys + i * 16));
    m = _mm_aesdec_si128(m, _mm_aesimc_si128(rk));
  }
  m = _mm_aesdeclast_si128(
      m, _mm_loadu_si128(reinterpret_cast<const __m128i *>(roundKeys)));
  _mm_storeu_si128(reinterpret_cast<__m128i *>(out), m);
}
#endif

void AES::EncryptBlock(const unsigned char in[], unsigned char out[],
                       const unsigned char *roundKeys) {
#if defined(__AES__) && (defined(__x86_64__) || defined(_M_X64) || \
                         defined(__i386) || defined(_M_IX86))
  static bool useAESNI = has_aesni();
  if (useAESNI) {
    EncryptBlockAESNI(in, out, roundKeys, Nr);
    return;
  }
#endif
  unsigned char state[4][Nb];
  unsigned int i, j, round;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys);

  for (round = 1; round <= Nr - 1; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);
  }

  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }
  secure_zero(state, sizeof(state));
}

void AES::GF_Multiply(const unsigned char *X, const unsigned char *Y,
                      unsigned char *Z) {
#if defined(__PCLMUL__) && (defined(__x86_64__) || defined(_M_X64) || \
                            defined(__i386) || defined(_M_IX86))
  if (has_pclmul()) {
    const __m128i a = _mm_loadu_si128(reinterpret_cast<const __m128i *>(X));
    const __m128i b = _mm_loadu_si128(reinterpret_cast<const __m128i *>(Y));

    const __m128i swap =
        _mm_set_epi8(0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06,
                     0x05, 0x04, 0x03, 0x02, 0x01, 0x00);
    __m128i x = _mm_shuffle_epi8(a, swap);
    __m128i y = _mm_shuffle_epi8(b, swap);

    const __m128i z0 = _mm_clmulepi64_si128(x, y, 0x00);
    const __m128i z1 = _mm_clmulepi64_si128(x, y, 0x10);
    const __m128i z2 = _mm_clmulepi64_si128(x, y, 0x01);
    const __m128i z3 = _mm_clmulepi64_si128(x, y, 0x11);

    const __m128i t = _mm_xor_si128(z1, z2);
    const __m128i t_lo = _mm_slli_si128(t, 8);
    const __m128i t_hi = _mm_srli_si128(t, 8);

    __m128i low = _mm_xor_si128(z0, t_lo);
    __m128i high = _mm_xor_si128(z3, t_hi);

    const __m128i R128 = _mm_set_epi32(0, 0, 0, 0x87);
    __m128i tmp = _mm_clmulepi64_si128(high, R128, 0x00);
    __m128i tmp2 = _mm_clmulepi64_si128(_mm_srli_si128(high, 8), R128, 0x00);
    tmp = _mm_xor_si128(tmp, _mm_slli_si128(tmp2, 8));
    low = _mm_xor_si128(low, tmp);
    tmp2 = _mm_clmulepi64_si128(tmp, R128, 0x00);
    low = _mm_xor_si128(low, _mm_slli_si128(tmp2, 8));

    low = _mm_shuffle_epi8(low, swap);
    _mm_storeu_si128(reinterpret_cast<__m128i *>(Z), low);
    return;
  }
#endif
  unsigned char V[16];
  unsigned char X_copy[16];
  memcpy(X_copy, X, 16);
  memset(Z, 0, 16);
  memcpy(V, Y, 16);

  for (int i = 0; i < 128; i++) {
    unsigned char bit = (X_copy[i / 8] >> (7 - (i % 8))) & 1;
    unsigned char mask = static_cast<unsigned char>(-bit);
    for (int j = 0; j < 16; j++) {
      Z[j] ^= V[j] & mask;
    }

    // Shift V left
    unsigned char carry = V[0] & 0x80;  // Preserve most significant bit

    for (int j = 0; j < 15; j++) {
      V[j] = (V[j] << 1) | (V[j + 1] >> 7);
    }

    V[15] <<= 1;

    unsigned char rmask =
        static_cast<unsigned char>(-(static_cast<unsigned char>(carry >> 7)));
    for (int j = 0; j < 16; j++) {
      V[j] ^= R[j] & rmask;
    }
  }
  secure_zero(X_copy, sizeof(X_copy));
  secure_zero(V, sizeof(V));
}

void AES::GHASH(const unsigned char *H, const unsigned char *X, size_t len,
                unsigned char *tag) {
  unsigned char block[16] = {0};
  memcpy(block, X, len);

  for (int j = 0; j < 16; j++) {
    tag[j] ^= block[j];
  }

  GF_Multiply(tag, H, tag);
  secure_zero(block, sizeof(block));
}

void AES::DecryptBlock(const unsigned char in[], unsigned char out[],
                       const unsigned char *roundKeys) {
#if defined(__AES__) && (defined(__x86_64__) || defined(_M_X64) || \
                         defined(__i386) || defined(_M_IX86))
  static bool useAESNI = has_aesni();
  if (useAESNI) {
    DecryptBlockAESNI(in, out, roundKeys, Nr);
    return;
  }
#endif
  unsigned char state[4][Nb];
  unsigned int i, j, round;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = in[i + 4 * j];
    }
  }

  AddRoundKey(state, roundKeys + Nr * 4 * Nb);

  for (round = Nr - 1; round >= 1; round--) {
    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, roundKeys + round * 4 * Nb);
    InvMixColumns(state);
  }

  InvSubBytes(state);
  InvShiftRows(state);
  AddRoundKey(state, roundKeys);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      out[i + 4 * j] = state[i][j];
    }
  }
  secure_zero(state, sizeof(state));
}

void AES::SubBytes(unsigned char state[4][Nb]) {
  unsigned int i, j;
  unsigned char t;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      t = state[i][j];
      state[i][j] = sbox[t];
    }
  }
}

void AES::ShiftRow(unsigned char state[4][Nb], unsigned int i,
                   unsigned int n) {  // shift row i on n positions
  unsigned char tmp[Nb];

  for (unsigned int j = 0; j < Nb; j++) {
    tmp[j] = state[i][(j + n) % Nb];
  }

  memcpy(state[i], tmp, Nb * sizeof(unsigned char));
  secure_zero(tmp, sizeof(tmp));
}

void AES::ShiftRows(unsigned char state[4][Nb]) {
  ShiftRow(state, 1, 1);
  ShiftRow(state, 2, 2);
  ShiftRow(state, 3, 3);
}

unsigned char AES::xtime(unsigned char b) {  // multiply on x
  return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::MixColumns(unsigned char state[4][Nb]) {
  for (size_t j = 0; j < Nb; ++j) {
    const unsigned char s0 = state[0][j];
    const unsigned char s1 = state[1][j];
    const unsigned char s2 = state[2][j];
    const unsigned char s3 = state[3][j];

    state[0][j] = GF_MUL_TABLE[2][s0] ^ GF_MUL_TABLE[3][s1] ^ s2 ^ s3;
    state[1][j] = s0 ^ GF_MUL_TABLE[2][s1] ^ GF_MUL_TABLE[3][s2] ^ s3;
    state[2][j] = s0 ^ s1 ^ GF_MUL_TABLE[2][s2] ^ GF_MUL_TABLE[3][s3];
    state[3][j] = GF_MUL_TABLE[3][s0] ^ s1 ^ s2 ^ GF_MUL_TABLE[2][s3];
  }
}

void AES::AddRoundKey(unsigned char state[4][Nb], const unsigned char *key) {
  unsigned int i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[i][j] = state[i][j] ^ key[i + 4 * j];
    }
  }
}

void AES::SubWord(unsigned char *a) {
  int i;

  for (i = 0; i < 4; i++) {
    a[i] = sbox[a[i]];
  }
}

void AES::RotWord(unsigned char *a) {
  unsigned char c = a[0];
  a[0] = a[1];
  a[1] = a[2];
  a[2] = a[3];
  a[3] = c;
}

void AES::XorWords(unsigned char *a, unsigned char *b, unsigned char *c) {
  int i;

  for (i = 0; i < 4; i++) {
    c[i] = a[i] ^ b[i];
  }
}

void AES::Rcon(unsigned char *a, unsigned int n) {
  a[0] = RCON_TABLE[n - 1];
  a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion(const unsigned char key[], unsigned char w[]) {
  unsigned char temp[4];
  unsigned char rcon[4];

  unsigned int i = 0;

  std::memcpy(w, key, 4 * Nk);
  i = 4 * Nk;

  while (i < 4 * Nb * (Nr + 1)) {
    temp[0] = w[i - 4 + 0];
    temp[1] = w[i - 4 + 1];
    temp[2] = w[i - 4 + 2];
    temp[3] = w[i - 4 + 3];

    if (i / 4 % Nk == 0) {
      RotWord(temp);
      SubWord(temp);
      Rcon(rcon, i / (Nk * 4));
      XorWords(temp, rcon, temp);
    }

    else if (Nk > 6 && i / 4 % Nk == 4) {
      SubWord(temp);
    }

    w[i + 0] = w[i - 4 * Nk] ^ temp[0];
    w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
    w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
    w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
    i += 4;
  }
  secure_zero(temp, sizeof(temp));
  secure_zero(rcon, sizeof(rcon));
}

void AES::InvSubBytes(unsigned char state[4][Nb]) {
  unsigned int i, j;
  unsigned char t;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      t = state[i][j];
      state[i][j] = inv_sbox[t];
    }
  }
}

void AES::InvMixColumns(unsigned char state[4][Nb]) {
  for (size_t j = 0; j < Nb; ++j) {
    const unsigned char s0 = state[0][j];
    const unsigned char s1 = state[1][j];
    const unsigned char s2 = state[2][j];
    const unsigned char s3 = state[3][j];

    state[0][j] = GF_MUL_TABLE[14][s0] ^ GF_MUL_TABLE[11][s1] ^
                  GF_MUL_TABLE[13][s2] ^ GF_MUL_TABLE[9][s3];
    state[1][j] = GF_MUL_TABLE[9][s0] ^ GF_MUL_TABLE[14][s1] ^
                  GF_MUL_TABLE[11][s2] ^ GF_MUL_TABLE[13][s3];
    state[2][j] = GF_MUL_TABLE[13][s0] ^ GF_MUL_TABLE[9][s1] ^
                  GF_MUL_TABLE[14][s2] ^ GF_MUL_TABLE[11][s3];
    state[3][j] = GF_MUL_TABLE[11][s0] ^ GF_MUL_TABLE[13][s1] ^
                  GF_MUL_TABLE[9][s2] ^ GF_MUL_TABLE[14][s3];
  }
}

void AES::InvShiftRows(unsigned char state[4][Nb]) {
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char *a, const unsigned char *b,
                    unsigned char *c, size_t len) noexcept {
#if defined(__SSE2__)
  size_t i = 0;
  for (; i + 16 <= len; i += 16) {
    __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i *>(a + i));
    __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i *>(b + i));
    __m128i vc = _mm_xor_si128(va, vb);
    _mm_storeu_si128(reinterpret_cast<__m128i *>(c + i), vc);
  }
#if AESCPP_HAS_UNALIGNED_UINT64
  // Use direct uint64_t loads when alignment isn't required
  for (; i + 8 <= len; i += 8) {
    uint64_t va = *reinterpret_cast<const uint64_t *>(a + i);
    uint64_t vb = *reinterpret_cast<const uint64_t *>(b + i);
    *reinterpret_cast<uint64_t *>(c + i) = va ^ vb;
  }
#else
  for (; i + 8 <= len; i += 8) {
    uint64_t va;
    uint64_t vb;
    std::memcpy(&va, a + i, sizeof(va));
    std::memcpy(&vb, b + i, sizeof(vb));
    uint64_t vc = va ^ vb;
    std::memcpy(c + i, &vc, sizeof(vc));
  }
#endif
  // Remaining bytes
  for (; i < len; ++i) {
    c[i] = a[i] ^ b[i];
  }
#else
  size_t i = 0;
#if AESCPP_HAS_UNALIGNED_UINT64
  // Use direct uint64_t loads when alignment isn't required
  for (; i + 8 <= len; i += 8) {
    uint64_t va = *reinterpret_cast<const uint64_t *>(a + i);
    uint64_t vb = *reinterpret_cast<const uint64_t *>(b + i);
    *reinterpret_cast<uint64_t *>(c + i) = va ^ vb;
  }
#else
  for (; i + 8 <= len; i += 8) {
    uint64_t va;
    uint64_t vb;
    std::memcpy(&va, a + i, sizeof(va));
    std::memcpy(&vb, b + i, sizeof(vb));
    uint64_t vc = va ^ vb;
    std::memcpy(c + i, &vc, sizeof(vc));
  }
#endif
  // Remaining bytes
  for (; i < len; ++i) {
    c[i] = a[i] ^ b[i];
  }
#endif
}

void AES::printHexArray(unsigned char a[], size_t n) {
  for (size_t i = 0; i < n; i++) {
    printf("%02x ", a[i]);
  }
}

void AES::printHexVector(const std::vector<unsigned char> &a) {
  for (size_t i = 0; i < a.size(); i++) {
    printf("%02x ", a[i]);
  }
}

void AES::printHexVector(std::vector<unsigned char> &&a) {
  for (size_t i = 0; i < a.size(); i++) {
    printf("%02x ", a[i]);
  }
}

std::vector<unsigned char> AES::ArrayToVector(unsigned char *a, size_t len) {
  std::vector<unsigned char> v(a, a + len);
  return v;
}
AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  std::vector<unsigned char> out(in.size());
  EncryptECB(in.data(), in.size(), key.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptECB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key) {
  std::vector<unsigned char> out(in.size());
  EncryptECB(in.data(), in.size(), key.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  std::vector<unsigned char> out(in.size());
  DecryptECB(in.data(), in.size(), key.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptECB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key) {
  std::vector<unsigned char> out(in.size());
  DecryptECB(in.data(), in.size(), key.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::vector<unsigned char> out(in.size());
  EncryptCBC(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCBC(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::vector<unsigned char> out(in.size());
  EncryptCBC(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::vector<unsigned char> out(in.size());
  DecryptCBC(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCBC(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::vector<unsigned char> out(in.size());
  DecryptCBC(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::vector<unsigned char> out(in.size());
  EncryptCFB(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCFB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::vector<unsigned char> out(in.size());
  EncryptCFB(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::vector<unsigned char> out(in.size());
  DecryptCFB(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCFB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::vector<unsigned char> out(in.size());
  DecryptCFB(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::vector<unsigned char> out(in.size());
  EncryptCTR(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCTR(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::vector<unsigned char> out(in.size());
  EncryptCTR(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::vector<unsigned char> out(in.size());
  DecryptCTR(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCTR(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::vector<unsigned char> out(in.size());
  DecryptCTR(in.data(), in.size(), key.data(), iv.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptGCM(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad,
    std::vector<unsigned char> &tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::vector<unsigned char> out(in.size());
  EncryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
             aad.size(), tag.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptGCM(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv, std::vector<unsigned char> &&aad,
    std::vector<unsigned char> &tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() > 16)
    throw std::invalid_argument("Tag size must be at most 16 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::vector<unsigned char> out(in.size());
  EncryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
             aad.size(), tag.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptGCM(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad,
    const std::vector<unsigned char> &tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() > 16)
    throw std::invalid_argument("Tag size must be at most 16 bytes");
  std::vector<unsigned char> tagCopy = tag;
  if (tagCopy.size() < 16) tagCopy.resize(16);
  std::vector<unsigned char> out(in.size());
  DecryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
             aad.size(), tagCopy.data(), out.data());
  return out;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptGCM(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv, std::vector<unsigned char> &&aad,
    std::vector<unsigned char> &&tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() > 16)
    throw std::invalid_argument("Tag size must be at most 16 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::vector<unsigned char> out(in.size());
  DecryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
             aad.size(), tag.data(), out.data());
  return out;
}

}  // namespace aescpp
