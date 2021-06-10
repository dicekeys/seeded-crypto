#pragma once

#include <string>
#include "ByteBuffer.hpp"
#include "../convert.hpp"

const std::string fiveDashes = "-----";

const std::string base64Blocks(const std::vector<unsigned char> &data) {
  const size_t size = sodium_base64_ENCODED_LEN(data.size(), sodium_base64_VARIANT_ORIGINAL);
  SodiumBuffer base64StrBuffer(size);
  sodium_bin2base64((char*) base64StrBuffer.data, size, data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL);
  const std::string base64((char*)base64StrBuffer.data, size - 1);
  std::string result;
  for (size_t index = 0; index < base64.size(); index += 64) {
      if (index > 0) {
          result += "\n";
      }
      result += base64.substr(index, 64);
  }
  return result;
}

const std::string PEM(const std::string type, ByteBuffer data) {
    return fiveDashes + "BEGIN " + type + fiveDashes + "\n" +
        base64Blocks(data.byteVector) + "\n" +
        fiveDashes + "END " + type + fiveDashes + "\n";
}
