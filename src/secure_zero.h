#pragma once

#include <cstddef>
#include <cstring>

#if defined(__has_include)
#if __has_include(<strings.h>)
#include <strings.h>
#endif
#endif

#if defined(_WIN32)
#include <windows.h>
#endif

inline void secure_zero(void *p, size_t n) {
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
