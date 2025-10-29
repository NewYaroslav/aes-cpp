#include "aes_cpp/aes.hpp"

int main() {
  // Access a debug-only method to detect API divergence.
  auto fn = &aes_cpp::AES::printHexArray;
  (void)fn;
  return 0;
}