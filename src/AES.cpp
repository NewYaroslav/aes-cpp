#include "AES.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <stdexcept>

#include "secure_zero.h"

static bool constant_time_eq(const unsigned char *a, const unsigned char *b,
                             size_t len) {
  unsigned char diff = 0;
  for (size_t i = 0; i < len; ++i) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

static constexpr unsigned char R[16] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0x87};  // Полином: x^128 + x^7 + x^2 + x + 1

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
  secure_zero(cachedRoundKeys.data(), cachedRoundKeys.size());
  secure_zero(cachedKey.data(), cachedKey.size());
}

unsigned char *AES::EncryptECB(const unsigned char in[], size_t inLen,
                               const unsigned char key[]) {
  CheckLength(inLen);
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(in + i, out.get() + i, roundKeys.data());
  }

  return out.release();
}

unsigned char *AES::DecryptECB(const unsigned char in[], size_t inLen,
                               const unsigned char key[]) {
  CheckLength(inLen);
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out.get() + i, roundKeys.data());
  }

  return out.release();
}

unsigned char *AES::EncryptCBC(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  CheckLength(inLen);
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    XorBlocks(block, in + i, block, blockBytesLen);
    EncryptBlock(block, out.get() + i, roundKeys.data());
    memcpy(block, out.get() + i, blockBytesLen);
  }

  secure_zero(block, sizeof(block));
  return out.release();
}

unsigned char *AES::DecryptCBC(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  CheckLength(inLen);
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out.get() + i, roundKeys.data());
    XorBlocks(block, out.get() + i, out.get() + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }

  secure_zero(block, sizeof(block));
  return out.release();
}

unsigned char *AES::EncryptCFB(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys.data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out.get() + i, blockLen);
    memcpy(block, out.get() + i, blockLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(encryptedBlock, sizeof(encryptedBlock));
  return out.release();
}

unsigned char *AES::DecryptCFB(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, roundKeys.data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out.get() + i, blockLen);
    memcpy(block, in + i, blockLen);
  }

  secure_zero(block, sizeof(block));
  secure_zero(encryptedBlock, sizeof(encryptedBlock));
  return out.release();
}

unsigned char *AES::EncryptCTR(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char iv[]) {
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);
  unsigned char counter[blockBytesLen];
  unsigned char encryptedCounter[blockBytesLen];
  memcpy(counter, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(counter, encryptedCounter, roundKeys.data());

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

unsigned char *AES::DecryptCTR(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char iv[]) {
  return EncryptCTR(in, inLen, key, iv);
}

unsigned char *AES::EncryptGCM(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char iv[],
                               const unsigned char aad[], size_t aadLen,
                               unsigned char tag[]) {
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);

  // Генерация H
  unsigned char H[16] = {0};
  unsigned char zeroBlock[16] = {0};
  EncryptBlock(zeroBlock, H, roundKeys.data());

  // Шифрование данных в режиме CTR
  unsigned char ctr[16] = {0};
  memcpy(ctr, iv, 12);  // IV занимает 12 байт
  ctr[15] = 1;  // Установить начальное значение счетчика
  unsigned char encryptedCtr[16] = {0};

  // GHASH для AAD без промежуточных буферов
  memset(tag, 0, 16);
  for (size_t i = 0; i < aadLen; i += 16) {
    GHASH(H, aad + i, std::min<size_t>(16, aadLen - i), tag);
  }

  for (size_t i = 0; i < inLen; i += 16) {
    EncryptBlock(ctr, encryptedCtr, roundKeys.data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out.get() + i, blockLen);
    GHASH(H, out.get() + i, blockLen, tag);

    // Увеличиваем счетчик
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
  EncryptBlock(J0, S, roundKeys.data());
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

unsigned char *AES::DecryptGCM(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char iv[],
                               const unsigned char aad[], size_t aadLen,
                               const unsigned char tag[]) {
  std::vector<unsigned char> roundKeys;
  {
    std::lock_guard<std::mutex> lock(cacheMutex);
    const size_t keyLen = 4 * Nk;
    if (cachedKey.size() != keyLen ||
        !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
      cachedKey.assign(key, key + keyLen);
      if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
        cachedRoundKeys.resize(4 * Nb * (Nr + 1));
      KeyExpansion(key, cachedRoundKeys.data());
    }
    roundKeys = cachedRoundKeys;
  }
  auto out = std::make_unique<unsigned char[]>(inLen);

  // Генерация H
  unsigned char H[16] = {0};
  unsigned char zeroBlock[16] = {0};
  EncryptBlock(zeroBlock, H, roundKeys.data());

  // Расшифровка данных в режиме CTR
  unsigned char ctr[16] = {0};
  memcpy(ctr, iv, 12);
  ctr[15] = 1;  // Установить начальное значение счетчика
  unsigned char encryptedCtr[16] = {0};

  unsigned char calculatedTag[16] = {0};
  // GHASH для AAD без формирования объединённого буфера
  for (size_t i = 0; i < aadLen; i += 16) {
    GHASH(H, aad + i, std::min<size_t>(16, aadLen - i), calculatedTag);
  }

  for (size_t i = 0; i < inLen; i += 16) {
    EncryptBlock(ctr, encryptedCtr, roundKeys.data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out.get() + i, blockLen);
    GHASH(H, in + i, blockLen, calculatedTag);

    // Увеличиваем счетчик
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
  EncryptBlock(J0, S, roundKeys.data());
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

void AES::EncryptBlock(const unsigned char in[], unsigned char out[],
                       unsigned char *roundKeys) {
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
  unsigned char V[16];
  memset(Z, 0, 16);
  memcpy(V, Y, 16);

  for (int i = 0; i < 128; i++) {
    if ((X[i / 8] >> (7 - (i % 8))) & 1) {
      for (int j = 0; j < 16; j++) {
        Z[j] ^= V[j];
      }
    }

    // Сдвиг V влево
    unsigned char carry = V[0] & 0x80;  // Сохранить старший бит

    for (int j = 0; j < 15; j++) {
      V[j] = (V[j] << 1) | (V[j + 1] >> 7);
    }

    V[15] <<= 1;

    // Если старший бит был установлен, применяем редукцию
    if (carry) {
      for (int j = 0; j < 16; j++) {
        V[j] ^= R[j];
      }
    }
  }
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
                       unsigned char *roundKeys) {
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
      state[i][j] = sbox[t / 16][t % 16];
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

void AES::AddRoundKey(unsigned char state[4][Nb], unsigned char *key) {
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
    a[i] = sbox[a[i] / 16][a[i] % 16];
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
  unsigned int i;
  unsigned char c = 1;

  for (i = 0; i < n - 1; i++) {
    c = xtime(c);
  }

  a[0] = c;
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
      state[i][j] = inv_sbox[t / 16][t % 16];
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
  for (size_t i = 0; i < len; i++) {
    c[i] = a[i] ^ b[i];
  }
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
  std::vector<unsigned char> v(a, a + len * sizeof(unsigned char));
  return v;
}

unsigned char *AES::VectorToArray(std::vector<unsigned char> &a) {
  return a.data();
}

std::vector<unsigned char> AES::EncryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  std::unique_ptr<unsigned char[]> out(
      EncryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptECB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key) {
  std::unique_ptr<unsigned char[]> out(
      EncryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  std::unique_ptr<unsigned char[]> out(
      DecryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptECB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key) {
  std::unique_ptr<unsigned char[]> out(
      DecryptECB(in.data(), in.size(), key.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptCBC(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptCBC(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCBC(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptCFB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptCFB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCFB(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptCTR(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      EncryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptCTR(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  std::unique_ptr<unsigned char[]> out(
      DecryptCTR(in.data(), in.size(), key.data(), iv.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::EncryptGCM(
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

std::vector<unsigned char> AES::EncryptGCM(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv,
                                           std::vector<unsigned char> &&aad,
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

std::vector<unsigned char> AES::DecryptGCM(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad,
    const std::vector<unsigned char> &tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  std::unique_ptr<unsigned char[]> out(
      DecryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
                 aad.size(), tag.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}

std::vector<unsigned char> AES::DecryptGCM(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv,
                                           std::vector<unsigned char> &&aad,
                                           std::vector<unsigned char> &&tag) {
  if (iv.size() != 12) throw std::invalid_argument("IV size must be 12 bytes");
  if (tag.size() < 16) tag.resize(16);
  std::unique_ptr<unsigned char[]> out(
      DecryptGCM(in.data(), in.size(), key.data(), iv.data(), aad.data(),
                 aad.size(), tag.data()));
  std::vector<unsigned char> v = ArrayToVector(out.get(), in.size());
  secure_zero(out.get(), in.size());
  return v;
}
