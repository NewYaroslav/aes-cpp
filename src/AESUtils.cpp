#include "AESUtils.h"

// Implementation for AES utility helpers.

namespace aesutils {

namespace detail {

bool fill_os_random(void *data, size_t len) noexcept {
#if defined(AESUTILS_HAVE_BCRYPT)
  NTSTATUS s =
      BCryptGenRandom(nullptr, static_cast<PUCHAR>(data),
                      static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return s == 0;

#elif defined(AESUTILS_HAVE_ARC4RANDOM)
  arc4random_buf(data, len);
  return true;

#elif defined(__linux__)
#if defined(AESUTILS_HAVE_GETRANDOM)
  {
    uint8_t *p = static_cast<uint8_t *>(data);
    size_t left = len;
    while (left > 0) {
      ssize_t r = getrandom(p, left, 0);
      if (r < 0) {
        if (errno == EINTR) continue;
        if (errno == ENOSYS) break;
        return false;
      }
      p += static_cast<size_t>(r);
      left -= static_cast<size_t>(r);
    }
    if (left == 0) return true;
  }
#endif
  int fd = open("/dev/urandom", O_RDONLY
#ifdef O_CLOEXEC
                                    | O_CLOEXEC
#endif
  );
  if (fd < 0) return false;
  uint8_t *p = static_cast<uint8_t *>(data);
  size_t left = len;
  while (left > 0) {
    ssize_t r = read(fd, p, left);
    if (r < 0) {
      if (errno == EINTR) continue;
      close(fd);
      return false;
    }
    if (r == 0) {
      close(fd);
      return false;
    }
    p += static_cast<size_t>(r);
    left -= static_cast<size_t>(r);
  }
  close(fd);
  return true;

#else
  (void)data;
  (void)len;
  return false;
#endif
}

}  // namespace detail

std::array<uint8_t, BLOCK_SIZE> generate_iv() {
  std::array<uint8_t, BLOCK_SIZE> iv{};

  if (detail::fill_os_random(iv.data(), iv.size())) return iv;

#if defined(AESUTILS_TRUST_STD_RANDOM_DEVICE)
  {
    std::random_device rd;
    for (auto &b : iv) b = static_cast<uint8_t>(rd());
    return iv;
  }
#endif

#if defined(AESUTILS_ALLOW_WEAK_FALLBACK)
  {
    auto now =
        std::chrono::high_resolution_clock::now().time_since_epoch().count();
    uint64_t seed = static_cast<uint64_t>(now);
    seed ^= (static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&seed)) << 13);
#if defined(_WIN32)
    seed ^= static_cast<uint64_t>(GetCurrentProcessId()) << 27;
#else
    seed ^= static_cast<uint64_t>(::getpid()) << 27;
#endif
    auto splitmix64 = [](uint64_t &x) noexcept {
      x += 0x9e3779b97f4a7c15ull;
      uint64_t z = x;
      z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
      z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
      return z ^ (z >> 31);
    };
    uint8_t *p = iv.data();
    size_t left = iv.size();
    while (left) {
      uint64_t r = splitmix64(seed);
      size_t take = left < sizeof(r) ? left : sizeof(r);
      std::memcpy(p, &r, take);
      p += take;
      left -= take;
    }
    return iv;
  }
#endif

  throw std::runtime_error(
      "No secure random source available on this platform");
}

std::vector<uint8_t> add_padding(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> padded = data;
  std::size_t padding = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
  padded.insert(padded.end(), padding, static_cast<uint8_t>(padding));
  return padded;
}

std::vector<uint8_t> remove_padding(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    throw std::invalid_argument("Data is empty, cannot remove padding.");
  }
  uint8_t padding = data.back();
  bool invalid = padding == 0 || padding > BLOCK_SIZE || padding > data.size();
  std::size_t to_check = padding;
  if (to_check > data.size()) {
    to_check = data.size();
  }
  std::size_t start = data.size() - to_check;
  for (std::size_t i = start; i < data.size(); ++i) {
    invalid |= (data[i] != padding);
  }
  if (invalid) {
    throw std::invalid_argument("Invalid padding detected.");
  }
  return std::vector<uint8_t>(data.begin(), data.end() - padding);
}

std::vector<uint8_t> add_iv_to_ciphertext(
    const std::vector<uint8_t> &ciphertext,
    const std::array<uint8_t, BLOCK_SIZE> &iv) {
  std::vector<uint8_t> result;
  result.reserve(iv.size() + ciphertext.size());
  result.insert(result.end(), iv.begin(), iv.end());
  result.insert(result.end(), ciphertext.begin(), ciphertext.end());
  return result;
}

std::vector<uint8_t> extract_iv_from_ciphertext(
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

  std::unique_ptr<unsigned char[]> encrypted;
  switch (mode) {
    case AesMode::CBC:
      encrypted.reset(
          aes.EncryptCBC(padded.data(), padded.size(), key.data(), iv.data()));
      break;
    case AesMode::CFB:
      encrypted.reset(
          aes.EncryptCFB(padded.data(), padded.size(), key.data(), iv.data()));
      break;
    default:
      throw std::invalid_argument("Invalid AES mode");
  }

  std::vector<uint8_t> ciphertext(encrypted.get(),
                                  encrypted.get() + padded.size());
  secure_zero(encrypted.get(), padded.size());
  secure_zero(padded.data(), padded.size());
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
  std::unique_ptr<unsigned char[]> decrypted;
  switch (mode) {
    case AesMode::CBC:
      decrypted.reset(aes.DecryptCBC(data.ciphertext.data(),
                                     data.ciphertext.size(), key.data(),
                                     data.iv.data()));
      break;
    case AesMode::CFB:
      decrypted.reset(aes.DecryptCFB(data.ciphertext.data(),
                                     data.ciphertext.size(), key.data(),
                                     data.iv.data()));
      break;
    default:
      throw std::invalid_argument("Invalid AES mode");
  }

  std::vector<uint8_t> plain(decrypted.get(),
                             decrypted.get() + data.ciphertext.size());
  secure_zero(decrypted.get(), data.ciphertext.size());
  auto result = remove_padding(plain);
  secure_zero(plain.data(), plain.size());
  return result;
}

template <class T>
std::string decrypt_to_string(const EncryptedData &data, const T &key,
                              AesMode mode) {
  std::vector<uint8_t> plain = decrypt(data, key, mode);
  std::string result(plain.begin(), plain.end());
  secure_zero(plain.data(), plain.size());
  return result;
}

template AESKeyLength key_length_from_key<std::vector<uint8_t>>(
    const std::vector<uint8_t> &);
template AESKeyLength key_length_from_key<std::array<uint8_t, 16>>(
    const std::array<uint8_t, 16> &);
template AESKeyLength key_length_from_key<std::array<uint8_t, 24>>(
    const std::array<uint8_t, 24> &);
template AESKeyLength key_length_from_key<std::array<uint8_t, 32>>(
    const std::array<uint8_t, 32> &);

template EncryptedData encrypt<std::vector<uint8_t>>(
    const std::vector<uint8_t> &, const std::vector<uint8_t> &, AesMode);
template EncryptedData encrypt<std::array<uint8_t, 16>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 16> &, AesMode);
template EncryptedData encrypt<std::array<uint8_t, 24>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 24> &, AesMode);
template EncryptedData encrypt<std::array<uint8_t, 32>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 32> &, AesMode);

template EncryptedData encrypt<std::vector<uint8_t>>(
    const std::string &, const std::vector<uint8_t> &, AesMode);
template EncryptedData encrypt<std::array<uint8_t, 16>>(
    const std::string &, const std::array<uint8_t, 16> &, AesMode);
template EncryptedData encrypt<std::array<uint8_t, 24>>(
    const std::string &, const std::array<uint8_t, 24> &, AesMode);
template EncryptedData encrypt<std::array<uint8_t, 32>>(
    const std::string &, const std::array<uint8_t, 32> &, AesMode);

template std::vector<uint8_t> decrypt<std::vector<uint8_t>>(
    const EncryptedData &, const std::vector<uint8_t> &, AesMode);
template std::vector<uint8_t> decrypt<std::array<uint8_t, 16>>(
    const EncryptedData &, const std::array<uint8_t, 16> &, AesMode);
template std::vector<uint8_t> decrypt<std::array<uint8_t, 24>>(
    const EncryptedData &, const std::array<uint8_t, 24> &, AesMode);
template std::vector<uint8_t> decrypt<std::array<uint8_t, 32>>(
    const EncryptedData &, const std::array<uint8_t, 32> &, AesMode);

template std::string decrypt_to_string<std::vector<uint8_t>>(
    const EncryptedData &, const std::vector<uint8_t> &, AesMode);
template std::string decrypt_to_string<std::array<uint8_t, 16>>(
    const EncryptedData &, const std::array<uint8_t, 16> &, AesMode);
template std::string decrypt_to_string<std::array<uint8_t, 24>>(
    const EncryptedData &, const std::array<uint8_t, 24> &, AesMode);
template std::string decrypt_to_string<std::array<uint8_t, 32>>(
    const EncryptedData &, const std::array<uint8_t, 32> &, AesMode);

}  // namespace aesutils
