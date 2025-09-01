#include "AES.h"

#include <algorithm>
#include <cstdint>
#include <cstring>

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

unsigned char *AES::EncryptECB(const unsigned char in[], size_t inLen,
                               const unsigned char key[]) {
  CheckLength(inLen);
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(in + i, out + i, cachedRoundKeys.data());
  }

  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptECB(const unsigned char in[], size_t inLen,
                               const unsigned char key[]) {
  CheckLength(inLen);
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, cachedRoundKeys.data());
  }

  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
}

unsigned char *AES::EncryptCBC(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  CheckLength(inLen);
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    XorBlocks(block, in + i, block, blockBytesLen);
    EncryptBlock(block, out + i, cachedRoundKeys.data());
    memcpy(block, out + i, blockBytesLen);
  }

  explicit_bzero(block, blockBytesLen);
  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptCBC(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  CheckLength(inLen);
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    DecryptBlock(in + i, out + i, cachedRoundKeys.data());
    XorBlocks(block, out + i, out + i, blockBytesLen);
    memcpy(block, in + i, blockBytesLen);
  }

  explicit_bzero(block, blockBytesLen);
  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
}

unsigned char *AES::EncryptCFB(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, cachedRoundKeys.data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out + i, blockLen);
    memcpy(block, out + i, blockLen);
  }

  explicit_bzero(block, blockBytesLen);
  explicit_bzero(encryptedBlock, blockBytesLen);
  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
}

unsigned char *AES::DecryptCFB(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char *iv) {
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  unsigned char block[blockBytesLen];
  unsigned char encryptedBlock[blockBytesLen];
  memcpy(block, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(block, encryptedBlock, cachedRoundKeys.data());
    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedBlock, out + i, blockLen);
    memcpy(block, in + i, blockLen);
  }

  explicit_bzero(block, blockBytesLen);
  explicit_bzero(encryptedBlock, blockBytesLen);
  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
}

unsigned char *AES::EncryptCTR(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char iv[]) {
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];
  unsigned char counter[blockBytesLen];
  unsigned char encryptedCounter[blockBytesLen];
  memcpy(counter, iv, blockBytesLen);

  for (size_t i = 0; i < inLen; i += blockBytesLen) {
    EncryptBlock(counter, encryptedCounter, cachedRoundKeys.data());

    size_t blockLen = std::min<size_t>(blockBytesLen, inLen - i);
    XorBlocks(in + i, encryptedCounter, out + i, blockLen);

    for (int j = blockBytesLen - 1; j >= 0; --j) {
      if (++counter[j] != 0) {
        break;
      }
    }
  }

  explicit_bzero(counter, blockBytesLen);
  explicit_bzero(encryptedCounter, blockBytesLen);
  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;

  return out;
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
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];

  // Генерация H
  unsigned char H[16] = {0};
  unsigned char zeroBlock[16] = {0};
  EncryptBlock(zeroBlock, H, cachedRoundKeys.data());

  // Шифрование данных в режиме CTR
  unsigned char ctr[16] = {0};
  memcpy(ctr, iv, 12);  // IV занимает 12 байт
  ctr[15] = 1;  // Установить начальное значение счетчика

  for (size_t i = 0; i < inLen; i += 16) {
    unsigned char encryptedCtr[16] = {0};
    EncryptBlock(ctr, encryptedCtr, cachedRoundKeys.data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out + i, blockLen);

    // Увеличиваем счетчик
    for (int j = 15; j >= 0; --j) {
      if (++ctr[j]) break;
    }

    explicit_bzero(encryptedCtr, 16);
  }

  // Вычисление тега с помощью GHASH
  size_t aad_padded_len = ((aadLen + 15) / 16) * 16;
  size_t data_padded_len = ((inLen + 15) / 16) * 16;
  size_t totalLen = aad_padded_len + data_padded_len + 16;
  unsigned char *ghashInput = new unsigned char[totalLen]();
  memcpy(ghashInput, aad, aadLen);
  memcpy(ghashInput + aad_padded_len, out, inLen);

  uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
  uint64_t lenBits = static_cast<uint64_t>(inLen) * 8;
  for (int i = 0; i < 8; i++)
    ghashInput[aad_padded_len + data_padded_len + i] =
        static_cast<unsigned char>(aadBits >> (56 - 8 * i));
  for (int i = 0; i < 8; i++)
    ghashInput[aad_padded_len + data_padded_len + 8 + i] =
        static_cast<unsigned char>(lenBits >> (56 - 8 * i));

  GHASH(H, ghashInput, totalLen, tag);
  unsigned char J0[16] = {0};
  memcpy(J0, iv, 12);
  J0[15] = 1;
  unsigned char S[16] = {0};
  EncryptBlock(J0, S, cachedRoundKeys.data());
  for (int i = 0; i < 16; i++) {
    tag[i] ^= S[i];
  }

  explicit_bzero(J0, 16);
  explicit_bzero(S, 16);
  explicit_bzero(H, 16);
  explicit_bzero(zeroBlock, 16);
  explicit_bzero(ctr, 16);
  explicit_bzero(ghashInput, totalLen);
  explicit_bzero(roundKeys, 4 * Nb * (Nr + 1));
  delete[] roundKeys;
  delete[] ghashInput;

  return out;
}

unsigned char *AES::DecryptGCM(const unsigned char in[], size_t inLen,
                               const unsigned char key[],
                               const unsigned char iv[],
                               const unsigned char aad[], size_t aadLen,
                               const unsigned char tag[]) {
  std::lock_guard<std::mutex> lock(cacheMutex);
  const size_t keyLen = 4 * Nk;
  if (cachedKey.size() != keyLen ||
      !std::equal(cachedKey.begin(), cachedKey.end(), key)) {
    cachedKey.assign(key, key + keyLen);
    if (cachedRoundKeys.size() != 4 * Nb * (Nr + 1))
      cachedRoundKeys.resize(4 * Nb * (Nr + 1));
    KeyExpansion(key, cachedRoundKeys.data());
  }
  unsigned char *out = new unsigned char[inLen];

  // Генерация H
  unsigned char H[16] = {0};
  unsigned char zeroBlock[16] = {0};
  EncryptBlock(zeroBlock, H, cachedRoundKeys.data());

  // Расшифровка данных в режиме CTR
  unsigned char ctr[16] = {0};
  memcpy(ctr, iv, 12);
  ctr[15] = 1;  // Установить начальное значение счетчика

  for (size_t i = 0; i < inLen; i += 16) {
    unsigned char encryptedCtr[16] = {0};
    EncryptBlock(ctr, encryptedCtr, cachedRoundKeys.data());

    size_t blockLen = std::min<size_t>(16, inLen - i);
    XorBlocks(in + i, encryptedCtr, out + i, blockLen);

    // Увеличиваем счетчик
    for (int j = 15; j >= 0; --j) {
      if (++ctr[j]) break;
    }

    explicit_bzero(encryptedCtr, 16);
  }

  // Проверка тега
  size_t aad_padded_len = ((aadLen + 15) / 16) * 16;
  size_t data_padded_len = ((inLen + 15) / 16) * 16;
  size_t totalLen = aad_padded_len + data_padded_len + 16;
  std::vector<unsigned char> ghashInput(totalLen, 0);
  memcpy(ghashInput.data(), aad, aadLen);
  memcpy(ghashInput.data() + aad_padded_len, in, inLen);

  uint64_t aadBits = static_cast<uint64_t>(aadLen) * 8;
  uint64_t lenBits = static_cast<uint64_t>(inLen) * 8;
  for (int i = 0; i < 8; i++)
    ghashInput[aad_padded_len + data_padded_len + i] =
        static_cast<unsigned char>(aadBits >> (56 - 8 * i));
  for (int i = 0; i < 8; i++)
    ghashInput[aad_padded_len + data_padded_len + 8 + i] =
        static_cast<unsigned char>(lenBits >> (56 - 8 * i));

  unsigned char calculatedTag[16] = {0};
  GHASH(H, ghashInput.data(), totalLen, calculatedTag);
  unsigned char J0[16] = {0};
  memcpy(J0, iv, 12);
  J0[15] = 1;
  unsigned char S[16] = {0};
  EncryptBlock(J0, S, cachedRoundKeys.data());
  for (int i = 0; i < 16; i++) {
    calculatedTag[i] ^= S[i];
  }

  explicit_bzero(roundKeys.data(), roundKeys.size());
  explicit_bzero(ghashInput.data(), ghashInput.size());
  explicit_bzero(H, 16);
  explicit_bzero(zeroBlock, 16);
  explicit_bzero(ctr, 16);

  if (memcmp(tag, calculatedTag, 16) != 0) {
    explicit_bzero(out, inLen);
    explicit_bzero(calculatedTag, 16);
    explicit_bzero(J0, 16);
    explicit_bzero(S, 16);
    delete[] out;
    throw std::runtime_error("Authentication failed");
  }

  explicit_bzero(calculatedTag, 16);
  explicit_bzero(J0, 16);
  explicit_bzero(S, 16);

  return out;
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
}

void AES::GF_Multiply(const unsigned char *X, const unsigned char *Y,
                      unsigned char *Z) {
  unsigned char V[16];
  unsigned char R[16] = {
      0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0x87};  // Полином: x^128 + x^7 + x^2 + x + 1
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
}

void AES::GHASH(const unsigned char *H, const unsigned char *X, size_t len,
                unsigned char *tag) {
  unsigned char Z[16] = {0};  // Инициализируем Z вектором нулей

  for (size_t i = 0; i < len; i += 16) {
    unsigned char block[16] = {0};

    // Копируем следующий блок данных
    size_t blockLen = std::min(len - i, (size_t)16);
    memcpy(block, X + i, blockLen);

    // XOR текущего блока с Z
    for (int j = 0; j < 16; j++) {
      Z[j] ^= block[j];
    }

    // Умножение в GF(2^128)
    GF_Multiply(Z, H, Z);
  }

  memcpy(tag, Z, 16);
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
  unsigned char *out = EncryptECB(in.data(), in.size(), key.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptECB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key) {
  unsigned char *out = EncryptECB(in.data(), in.size(), key.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptECB(
    const std::vector<unsigned char> &in,
    const std::vector<unsigned char> &key) {
  unsigned char *out = DecryptECB(in.data(), in.size(), key.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptECB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key) {
  unsigned char *out = DecryptECB(in.data(), in.size(), key.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  unsigned char *out = EncryptCBC(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptCBC(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  unsigned char *out = EncryptCBC(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptCBC(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  unsigned char *out = DecryptCBC(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptCBC(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  unsigned char *out = DecryptCBC(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  unsigned char *out = EncryptCFB(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptCFB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  unsigned char *out = EncryptCFB(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptCFB(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  unsigned char *out = DecryptCFB(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptCFB(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  unsigned char *out = DecryptCFB(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  unsigned char *out = EncryptCTR(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptCTR(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  unsigned char *out = EncryptCTR(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptCTR(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv) {
  unsigned char *out = DecryptCTR(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptCTR(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv) {
  unsigned char *out = DecryptCTR(in.data(), in.size(), key.data(), iv.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptGCM(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad,
    std::vector<unsigned char> &tag) {
  if (tag.size() < 16) tag.resize(16);
  unsigned char *out = EncryptGCM(in.data(), in.size(), key.data(), iv.data(),
                                  aad.data(), aad.size(), tag.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::EncryptGCM(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv,
                                           std::vector<unsigned char> &&aad,
                                           std::vector<unsigned char> &tag) {
  if (tag.size() < 16) tag.resize(16);
  unsigned char *out = EncryptGCM(in.data(), in.size(), key.data(), iv.data(),
                                  aad.data(), aad.size(), tag.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptGCM(
    const std::vector<unsigned char> &in, const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &iv, const std::vector<unsigned char> &aad,
    const std::vector<unsigned char> &tag) {
  unsigned char *out = DecryptGCM(in.data(), in.size(), key.data(), iv.data(),
                                  aad.data(), aad.size(), tag.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}

std::vector<unsigned char> AES::DecryptGCM(std::vector<unsigned char> &&in,
                                           std::vector<unsigned char> &&key,
                                           std::vector<unsigned char> &&iv,
                                           std::vector<unsigned char> &&aad,
                                           std::vector<unsigned char> &&tag) {
  if (tag.size() < 16) tag.resize(16);
  unsigned char *out = DecryptGCM(in.data(), in.size(), key.data(), iv.data(),
                                  aad.data(), aad.size(), tag.data());
  std::vector<unsigned char> v = ArrayToVector(out, in.size());
  explicit_bzero(out, in.size());
  delete[] out;
  return v;
}
