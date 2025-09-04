#ifndef AESUTILS_HAS_INCLUDE
#if defined(__has_include)
#define AESUTILS_HAS_INCLUDE(x) __has_include(x)
#else
#define AESUTILS_HAS_INCLUDE(x) 0
#endif
#endif

#if defined(_WIN32)
#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0601  // Windows 7 or later
#endif
#if !defined(WINVER)
#define WINVER _WIN32_WINNT
#endif
#if AESUTILS_HAS_INCLUDE(<bcrypt.h>)
#define AESUTILS_HAVE_BCRYPT 1
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt")
#endif
#endif
#elif defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__DragonFly__)
#define AESUTILS_HAVE_ARC4RANDOM 1
#include <stdlib.h>
#elif defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
// clang-format off
#if AESUTILS_HAS_INCLUDE(<sys/random.h>)
#define AESUTILS_HAVE_GETRANDOM 1
#include <sys/random.h>
#endif
// clang-format on
#endif

#include <aes_cpp/aes_utils.hpp>
#include <algorithm>
#include <functional>
#include <stdexcept>

#ifdef AESUTILS_TRUST_STD_RANDOM_DEVICE
#include <random>
#endif
#ifdef AESUTILS_ALLOW_WEAK_FALLBACK
#include <cstring>
#if !defined(_WIN32)
#include <unistd.h>
#else
#include <processthreadsapi.h>
#endif
#endif

// Implementation for AES utility helpers.

namespace aes_cpp {

namespace utils {

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

namespace {

template <std::size_t N>
std::array<uint8_t, N> generate_iv_impl() {
  std::array<uint8_t, N> iv{};
  if (detail::fill_os_random(iv.data(), iv.size())) return iv;

#if defined(AESUTILS_TRUST_STD_RANDOM_DEVICE)
  {
    std::random_device rd;
    std::size_t produced = 0;
    while (produced < iv.size()) {
      uint32_t r = rd();
      std::size_t to_copy = std::min(iv.size() - produced, sizeof(r));
      std::copy_n(reinterpret_cast<const uint8_t *>(&r), to_copy,
                  iv.begin() + static_cast<std::ptrdiff_t>(produced));
      produced += to_copy;
    }
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

bool constant_time_equal(const std::vector<uint8_t> &a,
                         const std::vector<uint8_t> &b) {
  // Length comparison and max_len computation are allowed only when the
  // vector sizes are public and not secret.
  std::size_t max_len = a.size();
  max_len +=
      (b.size() - max_len) & static_cast<std::size_t>(-(b.size() > max_len));
  std::size_t diff = a.size() ^ b.size();
  for (std::size_t i = 0; i < max_len; ++i) {
    const uint8_t av = i < a.size() ? a[i] : 0;
    const uint8_t bv = i < b.size() ? b[i] : 0;
    diff |= static_cast<std::size_t>(av ^ bv);
  }
  return diff == 0;
}

}  // namespace

std::array<uint8_t, 12> generate_iv_12() { return generate_iv_impl<12>(); }

std::array<uint8_t, 16> generate_iv_16() { return generate_iv_impl<16>(); }

std::vector<uint8_t> add_padding(const std::vector<uint8_t> &data) {
  std::vector<uint8_t> padded = data;
  std::size_t padding = BLOCK_SIZE - (data.size() % BLOCK_SIZE);
  padded.resize(data.size() + padding, static_cast<uint8_t>(padding));
  return padded;
}

bool remove_padding(const std::vector<uint8_t> &data,
                    std::vector<uint8_t> &out) noexcept {
  std::size_t len = data.size();
  uint8_t padding = len ? data.back() : 0;
  uint8_t invalid = 0;
  invalid |= static_cast<uint8_t>(len == 0);
  invalid |= static_cast<uint8_t>((len % BLOCK_SIZE) != 0);
  invalid |= static_cast<uint8_t>(padding == 0);
  invalid |= static_cast<uint8_t>(padding > BLOCK_SIZE);
  invalid |= static_cast<uint8_t>(padding > len);
  uint8_t diff = 0;
  for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
    uint8_t byte = 0;
    if (i < len) {
      byte = data[len - 1 - i];
    }
    uint8_t mask = static_cast<uint8_t>(0 - static_cast<uint8_t>(i < padding));
    diff |= (byte ^ padding) & mask;
  }
  size_t mask = -static_cast<size_t>((invalid | diff) == 0);
  size_t final_len = ((len - padding) & mask) | (len & ~mask);
  std::vector<uint8_t> tmp = data;
  tmp.resize(final_len);
  out.swap(tmp);
  return mask != 0;
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
                      AesMode mode, const MacFn &mac_fn) {
  AES aes(key_length_from_key(key));
  auto iv = generate_iv_16();
  const std::vector<uint8_t> *src = &plain;
  std::vector<uint8_t> padded;
  if (mode == AesMode::CBC) {
    padded = add_padding(plain);
    src = &padded;
  }

  std::vector<uint8_t> ciphertext(src->size());
  switch (mode) {
    case AesMode::CBC:
      aes.EncryptCBC(src->data(), src->size(), key.data(), iv.data(),
                     ciphertext.data());
      break;
    case AesMode::CFB:
      aes.EncryptCFB(src->data(), src->size(), key.data(), iv.data(),
                     ciphertext.data());
      break;
    case AesMode::CTR:
      aes.EncryptCTR(src->data(), src->size(), key.data(), iv.data(),
                     ciphertext.data());
      break;
    default:
      throw std::invalid_argument(
          "Invalid AES mode; expected CBC, CFB, or CTR");
  }
  if (mode == AesMode::CBC) {
    secure_zero(padded.data(), padded.size());
  }
  std::vector<uint8_t> tag;
  if (mac_fn) {
    auto mac_input = add_iv_to_ciphertext(ciphertext, iv);
    tag = mac_fn(mac_input);
  }
  return {std::chrono::system_clock::now(), iv, std::move(ciphertext),
          std::move(tag)};
}

template <class T>
EncryptedData encrypt(const std::string &plain_text, const T &key, AesMode mode,
                      const MacFn &mac_fn) {
  return encrypt(std::vector<uint8_t>(plain_text.begin(), plain_text.end()),
                 key, mode, mac_fn);
}

template <class T>
std::vector<uint8_t> decrypt(const EncryptedData &data, const T &key,
                             AesMode mode, const MacFn &mac_fn) {
  if (mac_fn) {
    auto mac_input = add_iv_to_ciphertext(data.ciphertext, data.iv);
    auto expected = mac_fn(mac_input);
    if (data.tag.empty() || !constant_time_equal(expected, data.tag)) {
      throw std::invalid_argument("MAC verification failed");
    }
  }
  AES aes(key_length_from_key(key));
  std::vector<uint8_t> plain(data.ciphertext.size());
  bool decrypt_error = false;
  try {
    switch (mode) {
      case AesMode::CBC:
        aes.DecryptCBC(data.ciphertext.data(), data.ciphertext.size(),
                       key.data(), data.iv.data(), plain.data());
        break;
      case AesMode::CFB:
        aes.DecryptCFB(data.ciphertext.data(), data.ciphertext.size(),
                       key.data(), data.iv.data(), plain.data());
        break;
      case AesMode::CTR:
        aes.DecryptCTR(data.ciphertext.data(), data.ciphertext.size(),
                       key.data(), data.iv.data(), plain.data());
        break;
      default:
        throw std::invalid_argument(
            "Invalid AES mode; expected CBC, CFB, or CTR");
    }
  } catch (const std::length_error &) {
    decrypt_error = true;
  }
  if (mode == AesMode::CBC) {
    std::vector<uint8_t> result;
    bool ok = remove_padding(plain, result);
    secure_zero(plain.data(), plain.size());
    if (decrypt_error || !ok) {
      secure_zero(result.data(), result.size());
      throw std::runtime_error("Invalid ciphertext");
    }
    return result;
  }
  if (decrypt_error) {
    secure_zero(plain.data(), plain.size());
    throw std::runtime_error("Invalid ciphertext");
  }
  return plain;
}

template <class T>
std::string decrypt_to_string(const EncryptedData &data, const T &key,
                              AesMode mode, const MacFn &mac_fn) {
  std::vector<uint8_t> plain = decrypt(data, key, mode, mac_fn);
  std::string result(plain.begin(), plain.end());
  secure_zero(plain.data(), plain.size());
  return result;
}

template <class T>
GcmEncryptedData encrypt_gcm(const std::vector<uint8_t> &plain, const T &key,
                             const std::vector<uint8_t> &aad) {
  AES aes(key_length_from_key(key));
  auto iv = generate_iv_12();
  std::array<uint8_t, 16> tag{};
  std::vector<uint8_t> ciphertext(plain.size());
  aes.EncryptGCM(plain.data(), plain.size(), key.data(), iv.data(),
                 aad.empty() ? nullptr : aad.data(), aad.size(), tag.data(),
                 ciphertext.data());
  return {std::chrono::system_clock::now(), iv, std::move(ciphertext), tag};
}

template <class T>
GcmEncryptedData encrypt_gcm(const std::string &plain_text, const T &key,
                             const std::vector<uint8_t> &aad) {
  return encrypt_gcm(std::vector<uint8_t>(plain_text.begin(), plain_text.end()),
                     key, aad);
}

template <class T>
std::vector<uint8_t> decrypt_gcm(const GcmEncryptedData &data, const T &key,
                                 const std::vector<uint8_t> &aad) {
  AES aes(key_length_from_key(key));
  std::vector<uint8_t> plain(data.ciphertext.size());
  aes.DecryptGCM(data.ciphertext.data(), data.ciphertext.size(), key.data(),
                 data.iv.data(), aad.empty() ? nullptr : aad.data(), aad.size(),
                 data.tag.data(), plain.data());
  return plain;
}

template <class T>
std::string decrypt_gcm_to_string(const GcmEncryptedData &data, const T &key,
                                  const std::vector<uint8_t> &aad) {
  std::vector<uint8_t> plain = decrypt_gcm(data, key, aad);
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
    const std::vector<uint8_t> &, const std::vector<uint8_t> &, AesMode,
    const MacFn &);
template EncryptedData encrypt<std::array<uint8_t, 16>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 16> &, AesMode,
    const MacFn &);
template EncryptedData encrypt<std::array<uint8_t, 24>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 24> &, AesMode,
    const MacFn &);
template EncryptedData encrypt<std::array<uint8_t, 32>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 32> &, AesMode,
    const MacFn &);

template EncryptedData encrypt<std::vector<uint8_t>>(
    const std::string &, const std::vector<uint8_t> &, AesMode, const MacFn &);
template EncryptedData encrypt<std::array<uint8_t, 16>>(
    const std::string &, const std::array<uint8_t, 16> &, AesMode,
    const MacFn &);
template EncryptedData encrypt<std::array<uint8_t, 24>>(
    const std::string &, const std::array<uint8_t, 24> &, AesMode,
    const MacFn &);
template EncryptedData encrypt<std::array<uint8_t, 32>>(
    const std::string &, const std::array<uint8_t, 32> &, AesMode,
    const MacFn &);

template std::vector<uint8_t> decrypt<std::vector<uint8_t>>(
    const EncryptedData &, const std::vector<uint8_t> &, AesMode,
    const MacFn &);
template std::vector<uint8_t> decrypt<std::array<uint8_t, 16>>(
    const EncryptedData &, const std::array<uint8_t, 16> &, AesMode,
    const MacFn &);
template std::vector<uint8_t> decrypt<std::array<uint8_t, 24>>(
    const EncryptedData &, const std::array<uint8_t, 24> &, AesMode,
    const MacFn &);
template std::vector<uint8_t> decrypt<std::array<uint8_t, 32>>(
    const EncryptedData &, const std::array<uint8_t, 32> &, AesMode,
    const MacFn &);

template std::string decrypt_to_string<std::vector<uint8_t>>(
    const EncryptedData &, const std::vector<uint8_t> &, AesMode,
    const MacFn &);
template std::string decrypt_to_string<std::array<uint8_t, 16>>(
    const EncryptedData &, const std::array<uint8_t, 16> &, AesMode,
    const MacFn &);
template std::string decrypt_to_string<std::array<uint8_t, 24>>(
    const EncryptedData &, const std::array<uint8_t, 24> &, AesMode,
    const MacFn &);
template std::string decrypt_to_string<std::array<uint8_t, 32>>(
    const EncryptedData &, const std::array<uint8_t, 32> &, AesMode,
    const MacFn &);

template GcmEncryptedData encrypt_gcm<std::vector<uint8_t>>(
    const std::vector<uint8_t> &, const std::vector<uint8_t> &,
    const std::vector<uint8_t> &);
template GcmEncryptedData encrypt_gcm<std::array<uint8_t, 16>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 16> &,
    const std::vector<uint8_t> &);
template GcmEncryptedData encrypt_gcm<std::array<uint8_t, 24>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 24> &,
    const std::vector<uint8_t> &);
template GcmEncryptedData encrypt_gcm<std::array<uint8_t, 32>>(
    const std::vector<uint8_t> &, const std::array<uint8_t, 32> &,
    const std::vector<uint8_t> &);

template GcmEncryptedData encrypt_gcm<std::vector<uint8_t>>(
    const std::string &, const std::vector<uint8_t> &,
    const std::vector<uint8_t> &);
template GcmEncryptedData encrypt_gcm<std::array<uint8_t, 16>>(
    const std::string &, const std::array<uint8_t, 16> &,
    const std::vector<uint8_t> &);
template GcmEncryptedData encrypt_gcm<std::array<uint8_t, 24>>(
    const std::string &, const std::array<uint8_t, 24> &,
    const std::vector<uint8_t> &);
template GcmEncryptedData encrypt_gcm<std::array<uint8_t, 32>>(
    const std::string &, const std::array<uint8_t, 32> &,
    const std::vector<uint8_t> &);

template std::vector<uint8_t> decrypt_gcm<std::vector<uint8_t>>(
    const GcmEncryptedData &, const std::vector<uint8_t> &,
    const std::vector<uint8_t> &);
template std::vector<uint8_t> decrypt_gcm<std::array<uint8_t, 16>>(
    const GcmEncryptedData &, const std::array<uint8_t, 16> &,
    const std::vector<uint8_t> &);
template std::vector<uint8_t> decrypt_gcm<std::array<uint8_t, 24>>(
    const GcmEncryptedData &, const std::array<uint8_t, 24> &,
    const std::vector<uint8_t> &);
template std::vector<uint8_t> decrypt_gcm<std::array<uint8_t, 32>>(
    const GcmEncryptedData &, const std::array<uint8_t, 32> &,
    const std::vector<uint8_t> &);

template std::string decrypt_gcm_to_string<std::vector<uint8_t>>(
    const GcmEncryptedData &, const std::vector<uint8_t> &,
    const std::vector<uint8_t> &);
template std::string decrypt_gcm_to_string<std::array<uint8_t, 16>>(
    const GcmEncryptedData &, const std::array<uint8_t, 16> &,
    const std::vector<uint8_t> &);
template std::string decrypt_gcm_to_string<std::array<uint8_t, 24>>(
    const GcmEncryptedData &, const std::array<uint8_t, 24> &,
    const std::vector<uint8_t> &);
template std::string decrypt_gcm_to_string<std::array<uint8_t, 32>>(
    const GcmEncryptedData &, const std::array<uint8_t, 32> &,
    const std::vector<uint8_t> &);

}  // namespace utils

}  // namespace aes_cpp
