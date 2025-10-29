#include <cstdlib>
#include <iostream>

#include "aes_cpp/aes.hpp"

int main() {
  std::cout << sizeof(aes_cpp::AES);
  return EXIT_SUCCESS;
}