#include "AES.h"
#include <cstdint>
#include <algorithm>

AES::AES (const AESKeyLength keyLength) {
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

unsigned char *AES::EncryptECB (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[]) {
    CheckLength (inLen);
    unsigned char *out = new unsigned char[inLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock (in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::DecryptECB (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[]) {
    CheckLength (inLen);
    unsigned char *out = new unsigned char[inLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock (in + i, out + i, roundKeys);
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::EncryptCBC (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[],
                                const unsigned char *iv) {
    CheckLength (inLen);
    unsigned char *out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);
    memcpy (block, iv, blockBytesLen);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        XorBlocks (block, in + i, block, blockBytesLen);
        EncryptBlock (block, out + i, roundKeys);
        memcpy (block, out + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::DecryptCBC (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[],
                                const unsigned char *iv) {
    CheckLength (inLen);
    unsigned char *out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);
    memcpy (block, iv, blockBytesLen);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        DecryptBlock (in + i, out + i, roundKeys);
        XorBlocks (block, out + i, out + i, blockBytesLen);
        memcpy (block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::EncryptCFB (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[],
                                const unsigned char *iv) {
    CheckLength (inLen);
    unsigned char *out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);
    memcpy (block, iv, blockBytesLen);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock (block, encryptedBlock, roundKeys);
        XorBlocks (in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy (block, out + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::DecryptCFB (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[],
                                const unsigned char *iv) {
    CheckLength (inLen);
    unsigned char *out = new unsigned char[inLen];
    unsigned char block[blockBytesLen];
    unsigned char encryptedBlock[blockBytesLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);
    memcpy (block, iv, blockBytesLen);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock (block, encryptedBlock, roundKeys);
        XorBlocks (in + i, encryptedBlock, out + i, blockBytesLen);
        memcpy (block, in + i, blockBytesLen);
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::EncryptCTR (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[], const unsigned char iv[]) {
    unsigned char *out = new unsigned char[inLen];
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];

    KeyExpansion (key, roundKeys);
    unsigned char counter[blockBytesLen];
    unsigned char encryptedCounter[blockBytesLen];
    memcpy (counter, iv, blockBytesLen);

    for (unsigned int i = 0; i < inLen; i += blockBytesLen) {
        EncryptBlock (counter, encryptedCounter, roundKeys);

        unsigned int blockLen = std::min (blockBytesLen, inLen - i);
        XorBlocks (in + i, encryptedCounter, out + i, blockLen);

        for (int j = blockBytesLen - 1; j >= 0; --j) {
            if (++counter[j] != 0) {
                break;
            }
        }
    }

    delete[] roundKeys;

    return out;
}

unsigned char *AES::DecryptCTR (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[], const unsigned char iv[]) {
    return EncryptCTR (in, inLen, key, iv);
}

unsigned char *AES::EncryptGCM (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[], const unsigned char iv[],
                                const unsigned char aad[], unsigned int aadLen,
                                unsigned char tag[]) {
    unsigned char *out = new unsigned char[inLen];

    // Генерация H
    unsigned char H[16] = {0};
    unsigned char zeroBlock[16] = {0};
    unsigned char *roundKeys = new unsigned char[4 * Nb * (Nr + 1)];
    KeyExpansion (key, roundKeys);
    EncryptBlock (zeroBlock, H, roundKeys);

    // Шифрование данных в режиме CTR
    unsigned char ctr[16] = {0};
    memcpy (ctr, iv, 12); // IV занимает 12 байт
    ctr[15] = 1; // Установить начальное значение счетчика

    for (unsigned int i = 0; i < inLen; i += 16) {
        unsigned char encryptedCtr[16] = {0};
        EncryptBlock (ctr, encryptedCtr, roundKeys);

        unsigned int blockLen = std::min (16u, inLen - i);
        XorBlocks (in + i, encryptedCtr, out + i, blockLen);

        // Увеличиваем счетчик
        for (int j = 15; j >= 0; --j) {
            if (++ctr[j])
                break;
        }
    }

    // Вычисление тега с помощью GHASH
    unsigned int totalLen = aadLen + inLen + 16;
    unsigned char *ghashInput = new unsigned char[totalLen]();
    memcpy (ghashInput, aad, aadLen);
    memcpy (ghashInput + aadLen, out, inLen);

    uint64_t aadBits = aadLen * 8;
    uint64_t lenBits = inLen * 8;
    for(int i=0;i<8;i++) ghashInput[aadLen+inLen+i]=(unsigned char)(aadBits>>(56-8*i));
    for(int i=0;i<8;i++) ghashInput[aadLen+inLen+8+i]=(unsigned char)(lenBits>>(56-8*i));

    GHASH (H, ghashInput, totalLen, tag);
    unsigned char J0[16] = {0};
    memcpy (J0, iv, 12);
    J0[15] = 1;
    unsigned char S[16] = {0};
    EncryptBlock (J0, S, roundKeys);
    for (int i = 0; i < 16; i++) {
        tag[i] ^= S[i];
    }

    delete[] roundKeys;
    delete[] ghashInput;

    return out;
}

unsigned char *AES::DecryptGCM (const unsigned char in[], unsigned int inLen,
                                const unsigned char key[], const unsigned char iv[],
                                const unsigned char aad[], unsigned int aadLen,
                                const unsigned char tag[]) {
    unsigned char *out = new unsigned char[inLen];

    // Генерация H
    unsigned char H[16] = {0};
    unsigned char zeroBlock[16] = {0};
    std::vector<unsigned char> roundKeys (4 * Nb * (Nr + 1));
    KeyExpansion (key, roundKeys.data ());
    EncryptBlock (zeroBlock, H, roundKeys.data ());

    // Расшифровка данных в режиме CTR
    unsigned char ctr[16] = {0};
    memcpy (ctr, iv, 12);
    ctr[15] = 1; // Установить начальное значение счетчика

    for (unsigned int i = 0; i < inLen; i += 16) {
        unsigned char encryptedCtr[16] = {0};
        EncryptBlock (ctr, encryptedCtr, roundKeys.data ());

        unsigned int blockLen = std::min (16u, inLen - i);
        XorBlocks (in + i, encryptedCtr, out + i, blockLen);

        // Увеличиваем счетчик
        for (int j = 15; j >= 0; --j) {
            if (++ctr[j])
                break;
        }
    }

    // Проверка тега
    unsigned int totalLen = aadLen + inLen + 16;
    std::vector<unsigned char> ghashInput (totalLen, 0);
    memcpy (ghashInput.data (), aad, aadLen);
    memcpy (ghashInput.data () + aadLen, in, inLen);

    uint64_t aadBits = aadLen * 8;
    uint64_t lenBits = inLen * 8;
    for(int i=0;i<8;i++) ghashInput.data()[aadLen+inLen+i]=(unsigned char)(aadBits>>(56-8*i));
    for(int i=0;i<8;i++) ghashInput.data()[aadLen+inLen+8+i]=(unsigned char)(lenBits>>(56-8*i));

    unsigned char calculatedTag[16] = {0};
    GHASH (H, ghashInput.data (), totalLen, calculatedTag);
    unsigned char J0[16] = {0};
    memcpy (J0, iv, 12);
    J0[15] = 1;
    unsigned char S[16] = {0};
    EncryptBlock (J0, S, roundKeys.data ());
    for (int i = 0; i < 16; i++) {
        calculatedTag[i] ^= S[i];
    }

    if (memcmp (tag, calculatedTag, 16) != 0) {
        delete[] out;
        throw std::runtime_error ("Authentication failed");
    }

    return out;
}

void AES::CheckLength (unsigned int len) {
    if (len % blockBytesLen != 0) {
        throw std::length_error ("Plaintext length must be divisible by " +
                                 std::to_string (blockBytesLen));
    }
}

void AES::EncryptBlock (const unsigned char in[], unsigned char out[],
                        unsigned char *roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey (state, roundKeys);

    for (round = 1; round <= Nr - 1; round++) {
        SubBytes (state);
        ShiftRows (state);
        MixColumns (state);
        AddRoundKey (state, roundKeys + round * 4 * Nb);
    }

    SubBytes (state);
    ShiftRows (state);
    AddRoundKey (state, roundKeys + Nr * 4 * Nb);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::GF_Multiply (const unsigned char *X, const unsigned char *Y,
                       unsigned char *Z) {
    unsigned char V[16];
    unsigned char R[16] = {0xE1}; // Полином: x^128 + x^7 + x^2 + x + 1
    memset (Z, 0, 16);
    memcpy (V, Y, 16);

    for (int i = 0; i < 128; i++) {
        if ((X[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; j++) {
                Z[j] ^= V[j];
            }
        }

        // Сдвиг V влево
        unsigned char carry = V[0] & 0x80; // Сохранить старший бит

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

void AES::GHASH (const unsigned char *H, const unsigned char *X, size_t len,
                 unsigned char *tag) {
    unsigned char Z[16] = {0}; // Инициализируем Z вектором нулей

    for (size_t i = 0; i < len; i += 16) {
        unsigned char block[16] = {0};

        // Копируем следующий блок данных
        size_t blockLen = std::min (len - i, (size_t)16);
        memcpy (block, X + i, blockLen);

        // XOR текущего блока с Z
        for (int j = 0; j < 16; j++) {
            Z[j] ^= block[j];
        }

        // Умножение в GF(2^128)
        GF_Multiply (Z, H, Z);
    }

    memcpy (tag, Z, 16);
}

void AES::DecryptBlock (const unsigned char in[], unsigned char out[],
                        unsigned char *roundKeys) {
    unsigned char state[4][Nb];
    unsigned int i, j, round;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = in[i + 4 * j];
        }
    }

    AddRoundKey (state, roundKeys + Nr * 4 * Nb);

    for (round = Nr - 1; round >= 1; round--) {
        InvSubBytes (state);
        InvShiftRows (state);
        AddRoundKey (state, roundKeys + round * 4 * Nb);
        InvMixColumns (state);
    }

    InvSubBytes (state);
    InvShiftRows (state);
    AddRoundKey (state, roundKeys);

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            out[i + 4 * j] = state[i][j];
        }
    }
}

void AES::SubBytes (unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = sbox[t / 16][t % 16];
        }
    }
}

void AES::ShiftRow (unsigned char state[4][Nb], unsigned int i,
                    unsigned int n) { // shift row i on n positions
    unsigned char tmp[Nb];

    for (unsigned int j = 0; j < Nb; j++) {
        tmp[j] = state[i][ (j + n) % Nb];
    }

    memcpy (state[i], tmp, Nb * sizeof (unsigned char));
}

void AES::ShiftRows (unsigned char state[4][Nb]) {
    ShiftRow (state, 1, 1);
    ShiftRow (state, 2, 2);
    ShiftRow (state, 3, 3);
}

unsigned char AES::xtime (unsigned char b) { // multiply on x
    return (b << 1) ^ (((b >> 7) & 1) * 0x1b);
}

void AES::MixColumns (unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset (temp_state[i], 0, 4);
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
        memcpy (state[i], temp_state[i], 4);
    }
}

void AES::AddRoundKey (unsigned char state[4][Nb], unsigned char *key) {
    unsigned int i, j;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            state[i][j] = state[i][j] ^ key[i + 4 * j];
        }
    }
}

void AES::SubWord (unsigned char *a) {
    int i;

    for (i = 0; i < 4; i++) {
        a[i] = sbox[a[i] / 16][a[i] % 16];
    }
}

void AES::RotWord (unsigned char *a) {
    unsigned char c = a[0];
    a[0] = a[1];
    a[1] = a[2];
    a[2] = a[3];
    a[3] = c;
}

void AES::XorWords (unsigned char *a, unsigned char *b, unsigned char *c) {
    int i;

    for (i = 0; i < 4; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::Rcon (unsigned char *a, unsigned int n) {
    unsigned int i;
    unsigned char c = 1;

    for (i = 0; i < n - 1; i++) {
        c = xtime (c);
    }

    a[0] = c;
    a[1] = a[2] = a[3] = 0;
}

void AES::KeyExpansion (const unsigned char key[], unsigned char w[]) {
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
            RotWord (temp);
            SubWord (temp);
            Rcon (rcon, i / (Nk * 4));
            XorWords (temp, rcon, temp);
        }

        else if (Nk > 6 && i / 4 % Nk == 4) {
            SubWord (temp);
        }

        w[i + 0] = w[i - 4 * Nk] ^ temp[0];
        w[i + 1] = w[i + 1 - 4 * Nk] ^ temp[1];
        w[i + 2] = w[i + 2 - 4 * Nk] ^ temp[2];
        w[i + 3] = w[i + 3 - 4 * Nk] ^ temp[3];
        i += 4;
    }
}

void AES::InvSubBytes (unsigned char state[4][Nb]) {
    unsigned int i, j;
    unsigned char t;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < Nb; j++) {
            t = state[i][j];
            state[i][j] = inv_sbox[t / 16][t % 16];
        }
    }
}

void AES::InvMixColumns (unsigned char state[4][Nb]) {
    unsigned char temp_state[4][Nb];

    for (size_t i = 0; i < 4; ++i) {
        memset (temp_state[i], 0, 4);
    }

    for (size_t i = 0; i < 4; ++i) {
        for (size_t k = 0; k < 4; ++k) {
            for (size_t j = 0; j < 4; ++j) {
                temp_state[i][j] ^= GF_MUL_TABLE[INV_CMDS[i][k]][state[k][j]];
            }
        }
    }

    for (size_t i = 0; i < 4; ++i) {
        memcpy (state[i], temp_state[i], 4);
    }
}

void AES::InvShiftRows (unsigned char state[4][Nb]) {
    ShiftRow (state, 1, Nb - 1);
    ShiftRow (state, 2, Nb - 2);
    ShiftRow (state, 3, Nb - 3);
}

void AES::XorBlocks (
        const unsigned char *a,
        const unsigned char *b,
        unsigned char *c,
        unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        c[i] = a[i] ^ b[i];
    }
}

void AES::printHexArray (unsigned char a[], unsigned int n) {
    for (unsigned int i = 0; i < n; i++) {
        printf ("%02x ", a[i]);
    }
}

void AES::printHexVector (std::vector<unsigned char> a) {
    for (unsigned int i = 0; i < a.size(); i++) {
        printf ("%02x ", a[i]);
    }
}

std::vector<unsigned char> AES::ArrayToVector (unsigned char *a,
        unsigned int len) {
    std::vector<unsigned char> v (a, a + len * sizeof (unsigned char));
    return v;
}

unsigned char *AES::VectorToArray (std::vector<unsigned char> &a) {
    return a.data();
}

std::vector<unsigned char> AES::EncryptECB (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key) {
    unsigned char *out = EncryptECB (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key));
    std::vector<unsigned char> v = ArrayToVector (out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptECB (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key) {
    unsigned char *out = DecryptECB (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key));
    std::vector<unsigned char> v = ArrayToVector (out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCBC (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv) {
    unsigned char *out = EncryptCBC (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv));
    std::vector<unsigned char> v = ArrayToVector (out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCBC (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv) {
    unsigned char *out = DecryptCBC (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv));
    std::vector<unsigned char> v = ArrayToVector (out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCFB (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv) {
    unsigned char *out = EncryptCFB (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv));
    std::vector<unsigned char> v = ArrayToVector (out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCFB (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv) {
    unsigned char *out = DecryptCFB (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv));
    std::vector<unsigned char> v = ArrayToVector (out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptCTR (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv) {
    unsigned char *out = EncryptCTR (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv));
    std::vector<unsigned char> v = ArrayToVector (out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptCTR (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv) {
    unsigned char *out = DecryptCTR (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv));
    std::vector<unsigned char> v = ArrayToVector (out, (unsigned int)in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::EncryptGCM (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv,
        std::vector<unsigned char> aad,
        std::vector<unsigned char> &tag) {
    if(tag.size()<16) tag.resize(16);
    unsigned char *out = EncryptGCM (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv),
                                     VectorToArray (aad), (unsigned int)aad.size(),
                                     VectorToArray (tag));
    std::vector<unsigned char> v = ArrayToVector (out, in.size());
    delete[] out;
    return v;
}

std::vector<unsigned char> AES::DecryptGCM (
        std::vector<unsigned char> in,
        std::vector<unsigned char> key,
        std::vector<unsigned char> iv,
        std::vector<unsigned char> aad,
        std::vector<unsigned char> tag) {
    if(tag.size()<16) tag.resize(16);
    unsigned char *out = DecryptGCM (VectorToArray (in), (unsigned int)in.size(),
                                     VectorToArray (key), VectorToArray (iv),
                                     VectorToArray (aad), (unsigned int)aad.size(),
                                     VectorToArray (tag));
    std::vector<unsigned char> v = ArrayToVector (out, (unsigned int)in.size());
    delete[] out;
    return v;
}
