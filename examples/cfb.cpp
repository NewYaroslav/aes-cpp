#include <aes_cpp/aes_utils.hpp>
#include <array>
#include <iostream>
#include <string>

int main() {
  using namespace aes_cpp;
  std::string text = "CFB example";
  std::array<uint8_t, 16> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                 0x0c, 0x0d, 0x0e, 0x0f};
  auto encrypted = utils::encrypt(text, key, utils::AesMode::CFB);
  auto decrypted =
      utils::decrypt_to_string(encrypted, key, utils::AesMode::CFB);
  std::cout << decrypted << std::endl;
  return 0;
}
