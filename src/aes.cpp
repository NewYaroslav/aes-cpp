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

static bool constant_time_eq(const unsigned char *a, const unsigned char *b,
                             size_t len) {
  unsigned char diff = 0;
  for (size_t i = 0; i < len; ++i) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || \
    defined(_M_IX86)
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
#else
static bool has_aesni() { return false; }
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
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    auto newRoundKeys =
        std::make_shared<std::vector<unsigned char>>(4 * Nb * (Nr + 1));
    KeyExpansion(key, newRoundKeys->data());
    cachedRoundKeys = newRoundKeys;
  }
  return cachedRoundKeys;
}

AESCPP_NODISCARD unsigned char *AES::EncryptECB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[]) {
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(in + i, out.get() + i, roundKeys->data());
  }

  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::DecryptECB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[]) {
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out.get() + i, roundKeys->data());
  }

  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::EncryptCBC(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  if (!key || !iv) throw std::invalid_argument("Null key or IV");
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    XorBlocks(block, in + i, block, blockBytesLen);
    EncryptBlock(block, out.get() + i, roundKeys->data());
    memcpy(block, out.get() + i, blockBytesLen);
  }

  secure_zero(block, sizeof(block));
  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::DecryptCBC(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  if (!key || !iv) throw std::invalid_argument("Null key or IV");
  CheckLength(inLen);
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out.get() + i, roundKeys->data());
    XorBlocks(block, out.get() + i, out.get() + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }

  secure_zero(block, sizeof(block));
  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::EncryptCFB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  if (!key || !iv) throw std::invalid_argument("Null key or IV");
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys->data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out.get() + i, blockLen);
    memcpy(block, out.get() + i, blockLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(encryptedBlock, sizeof(encryptedBlock));
  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::DecryptCFB(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char *iv) {
  if (!key || !iv) throw std::invalid_argument("Null key or IV");
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys->data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out.get() + i, blockLen);
    memcpy(block, in + i, blockLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(encryptedBlock, sizeof(encryptedBlock));
  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::EncryptCTR(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char iv[]) {
  if (!key || !iv) throw std::invalid_argument("Null key or IV");
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);
  unsigned char counter[blockBytesLen];
  unsigned char encryptedCounter[blockBytesLen];
  memcpy(counter, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(counter, encryptedCounter, roundKeys->data());

    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedCounter, out.get() + i, blockLen);

    for (int j = blockBytesLen - 1; j >= 0; --j) {
      if (++counter[j] != 0) {
        break;
      }
    }
  }

  secure_zero(counter, sizeof(counter));
  secure_zero(encryptedCounter, sizeof(encryptedCounter));
  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::DecryptCTR(const unsigned char in[],
                                                size_t inLen,
                                                const unsigned char key[],
                                                const unsigned char iv[]) {
  if (!key || !iv) throw std::invalid_argument("Null key or IV");
  return EncryptCTR(in, inLen, key, iv);
}

AESCPP_NODISCARD unsigned char *AES::EncryptGCM(
    const unsigned char in[], size_t inLen, const unsigned char key[],
    const unsigned char iv[], const unsigned char aad[], size_t aadLen,
    unsigned char tag[]) {
  if (!key || !iv || (!aad && aadLen > 0) || !tag)
    throw std::invalid_argument("Null key, IV, AAD or tag");
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);

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
    EncryptBlock(ctr, encryptedCtr, roundKeys->data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out.get() + i, blockLen);
    GHASH(H, out.get() + i, blockLen, tag);

    // Increment counter
    for (int j = 15; j >= 0; --j) {
      if (++ctr[j]) break;
    }
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
  return out.release();
}

AESCPP_NODISCARD unsigned char *AES::DecryptGCM(
    const unsigned char in[], size_t inLen, const unsigned char key[],
    const unsigned char iv[], const unsigned char aad[], size_t aadLen,
    const unsigned char tag[]) {
  if (!key || !iv || (!aad && aadLen > 0) || !tag)
    throw std::invalid_argument("Null key, IV, AAD or tag");
  auto roundKeys = prepare_round_keys(key);
  auto out = AESCPP_MAKE_UNIQUE(unsigned char, inLen);

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
    EncryptBlock(ctr, encryptedCtr, roundKeys->data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out.get() + i, blockLen);
    GHASH(H, in + i, blockLen, calculatedTag);

    // Increment counter
    for (int j = 15; j >= 0; --j) {
      if (++ctr[j]) break;
    }
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
    secure_zero(out.get(), inLen);
    throw std::runtime_error("Authentication failed");
  }

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
#else
  unsigned char V[16];
  memset(Z, 0, 16);
  memcpy(V, Y, 16);

  for (int i = 0; i < 128; i++) {
    if ((X[i / 8] >> (7 - (i % 8))) & 1) {
      for (int j = 0; j < 16; j++) {
        Z[j] ^= V[j];
      }
    }

    // Shift V left
    unsigned char carry = V[0] & 0x80;  // Preserve most significant bit

    for (int j = 0; j < 15; j++) {
      V[j] = (V[j] << 1) | (V[j + 1] >> 7);
    }

    V[15] <<= 1;

    // If the most significant bit was set, apply reduction
    if (carry) {
      for (int j = 0; j < 16; j++) {
        V[j] ^= R[j];
      }
    }
  }
  secure_zero(V, sizeof(V));
#endif
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
  unsigned char temp_state[4][Nb];

  for (size_t i = 0; i < 4; ++i) {
    memset(temp_state[i], 0, 4);
  }

  for (size_t i = 0; i < 4; ++i) {
    for (size_t k = 0; k < 4; ++k) {
      for (size_t j = 0; j < 4; ++j) {
        if (CMDS[i][k] == 1)
          temp_state[i][j] ^= state[k][j];
        else
          temp_state[i][j] ^= GF_MUL_TABLE[CMDS[i][k]][state[k][j]];
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    memcpy(state[i], temp_state[i], 4);
  }
  secure_zero(temp_state, sizeof(temp_state));
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

  while (i < 4 * Nk) {
    w[i] = key[i];
    i++;
  }

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
  unsigned char temp_state[4][Nb];

  for (size_t i = 0; i < 4; ++i) {
    memset(temp_state[i], 0, 4);
  }

  for (size_t i = 0; i < 4; ++i) {
    for (size_t k = 0; k < 4; ++k) {
      for (size_t j = 0; j < 4; ++j) {
        temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
      }
    }
  }

  for (size_t i = 0; i < 4; ++i) {
    memcpy(state[i], temp_state[i], 4);
  }
  secure_zero(temp_state, sizeof(temp_state));
}

void AES::InvShiftRows(unsigned char state[4][Nb]) {
  ShiftRow(state, 1, Nb - 1);
  ShiftRow(state, 2, Nb - 2);
  ShiftRow(state, 3, Nb - 3);
}

void AES::XorBlocks(const unsigned char *a, const unsigned char *b,
                    unsigned char *c, size_t len) {
#if defined(__SSE2__)
  size_t i = 0;
  for (; i + 16 <= len; i += 16) {
    __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i *>(a + i));
    __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i *>(b + i));
    __m128i vc = _mm_xor_si128(va, vb);
    _mm_storeu_si128(reinterpret_cast<__m128i *>(c + i), vc);
  }
  for (; i + 8 <= len; i += 8) {
    uint64_t va = *reinterpret_cast<const uint64_t *>(a + i);
    uint64_t vb = *reinterpret_cast<const uint64_t *>(b + i);
    *reinterpret_cast<uint64_t *>(c + i) = va ^ vb;
  }
  // Remaining bytes
  for (; i < len; ++i) {
    c[i] = a[i] ^ b[i];
  }
#else
  size_t i = 0;
  for (; i + 8 <= len; i += 8) {
    uint64_t va = *reinterpret_cast<const uint64_t *>(a + i);
    uint64_t vb = *reinterpret_cast<const uint64_t *>(b + i);
    *reinterpret_cast<uint64_t *>(c + i) = va ^ vb;
  }
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

unsigned char *AES::VectorToArray(std::vector<unsigned char> &a) {
  return a.data();
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  std::unique_ptr<unsigned char[]> out(
      EncryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptECB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key) {
  std::unique_ptr<unsigned char[]> out(
      EncryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  std::unique_ptr<unsigned char[]> out(
      DecryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptECB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key) {
  std::unique_ptr<unsigned char[]> out(
      DecryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCBC(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCBC(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCFB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCFB(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptCTR(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptCTR(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptGCM(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad,
    std::vector<unsigned char> &tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::unique_ptr<unsigned char[]> out(
      EncryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
                 aad.size(), tag.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::EncryptGCM(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv, std::vector<unsigned char> &&aad,
    std::vector<unsigned char> &tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() > 16)
    throw std::invalid_argument("Tag size must be at most 16 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::unique_ptr<unsigned char[]> out(
      EncryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
                 aad.size(), tag.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
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
  std::unique_ptr<unsigned char[]> out(
      DecryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
                 aad.size(), tagCopy.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

AESCPP_NODISCARD std::vector<unsigned char> AES::DecryptGCM(
    std::vector<unsigned char> &&in, std::vector<unsigned char> &&key,
    std::vector<unsigned char> &&iv, std::vector<unsigned char> &&aad,
    std::vector<unsigned char> &&tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() > 16)
    throw std::invalid_argument("Tag size must be at most 16 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::unique_ptr<unsigned char[]> out(
      DecryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
                 aad.size(), tag.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

}  // namespace aescpp
