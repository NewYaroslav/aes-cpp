#include <aes_cpp/aes_utils.hpp>
#include <array>
#include <iostream>
#include <string>
#include <vector>

int main() {
  using namespace aes_cpp;
  std::string text = "GCM example";
  std::array<uint8_t, 16> key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                 0x0c, 0x0d, 0x0e, 0x0f};
  std::vector<uint8_t> aad = {'h', 'e', 'a', 'd', 'e', 'r'};
  auto data = utils::encrypt_gcm(text, key, aad);
  auto plain = utils::decrypt_gcm_to_string(data, key, aad);
  std::cout << plain << std::endl;
  return 0;
}
