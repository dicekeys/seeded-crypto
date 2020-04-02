#include "convert.hpp"
#include <exception>
#include <stdexcept>

constexpr char hexDigits[] = {
  '0', '1', '2', '3', '4', '5', '6', '7',
  '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

std::string toHexStr(const std::vector<unsigned char> bytes)
{
  std::string hexString(bytes.size() * 2, ' ');
  int i = 0;
  for (const unsigned char b : bytes) {
    hexString[i++] = hexDigits[b >> 4];
    hexString[i++] = hexDigits[b & 0xf];
  }
  return hexString;
}

class InvalidHexCharacterException: public std::invalid_argument
{
  public:
  InvalidHexCharacterException(const char* what =
    "Could not parse non-hex character"
  ) :
    std::invalid_argument(what) {}
};

inline unsigned char parseHexChar(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  } else if (c >= 'a' && c <= 'f') {
    return 10 + (c - 'a');
  } else if (c >= 'A' && c <= 'F') {
    return 10 + (c - 'A');
  }
  throw InvalidHexCharacterException();
}

std::vector<unsigned char> hexStrToByteVector(const std::string hexStr)
{
  if (hexStr.length() >= 2 && hexStr[1] == 'x' && hexStr[0] == '0') {
    // Ignore prefix '0x'
    return hexStrToByteVector(hexStr.substr(2));
  }
  if (hexStr.length() % 2 == 1) {
    throw std::invalid_argument("Invalid hex string length");
  }
  std::vector<unsigned char> byteVector(hexStr.length() / 2);
  for (size_t i = 0; i < byteVector.size(); i++) {
    byteVector[i] = (parseHexChar(hexStr[2 * i]) << 4) | parseHexChar(hexStr[2 * i + 1]);
  }
  return byteVector;
}
