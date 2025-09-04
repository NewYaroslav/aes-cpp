#include <sys/time.h>

#include <aes_cpp/aes.hpp>
#include <aes_cpp/aes_utils.hpp>
#include <iostream>

const unsigned int MICROSECONDS = 1000000;
unsigned long getMicroseconds() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return MICROSECONDS * tv.tv_sec + tv.tv_usec;
}

// Generate plaintext filled with cryptographically secure random bytes.
unsigned char *getRandomPlain(unsigned int length) {
  unsigned char *plain = new unsigned char[length];
  aes_cpp::utils::detail::fill_os_random(plain, length);
  return plain;
}

int main() {
  const unsigned int MEGABYTE = 1024 * 1024 * sizeof(unsigned char);

  unsigned int megabytesCount = 10;
  unsigned int plainLength = megabytesCount * MEGABYTE;
  unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

  std::cout << "Start speedtest" << std::endl;

  // Plaintext is filled using secure OS randomness.
  unsigned char *plain = getRandomPlain(plainLength);

  aes_cpp::AES aes(aes_cpp::AESKeyLength::AES_256);
  unsigned long start = getMicroseconds();
  unsigned char *out = aes.EncryptECB(plain, plainLength, key);
  unsigned long delta = getMicroseconds() - start;

  double speed = (double)megabytesCount / delta * MICROSECONDS;

  printf("%.2f Mb/s\n", speed);

  delete[] plain;
  delete[] out;

  return 0;
}
