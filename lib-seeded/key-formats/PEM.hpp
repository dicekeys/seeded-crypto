#pragma once

#include <string>
#include "ByteBuffer.hpp"
#include "../convert.hpp"


#define CRC24_INIT 0xB704CEL
#define CRC24_GENERATOR 0x864CFBL

// Copied verbatim from
// https://www.ietf.org/archive/id/draft-ietf-openpgp-crypto-refresh-03.html#name-radix-64-conversions
typedef unsigned long crc24;
inline crc24 crc_octets(const unsigned char *octets, size_t len)
{
    crc24 crc = CRC24_INIT;
    int i;
    while (len--) {
        crc ^= (*octets++) << 16;
        for (i = 0; i < 8; i++) {
            crc <<= 1;
            if (crc & 0x1000000) {
                crc &= 0xffffff; /* Clear bit 25 to avoid overflow */
                crc ^= CRC24_GENERATOR;
            }
        }
    }
    return crc & 0xFFFFFFL;
}

const std::string fiveDashes = "-----";

inline const std::string base64Encode(const std::vector<unsigned char>& data) {
  const size_t size = sodium_base64_ENCODED_LEN(data.size(), sodium_base64_VARIANT_ORIGINAL);
  SodiumBuffer base64StrBuffer(size);
  sodium_bin2base64((char*)base64StrBuffer.data, size, data.data(), data.size(), sodium_base64_VARIANT_ORIGINAL);
  return std::string((char*)base64StrBuffer.data, size - 1);
}

inline const std::string checksumLine(const std::vector<unsigned char> &data) {
  unsigned long crc = crc_octets(data.data(), data.size());
  std::vector<uint8_t> checksum = {
    uint8_t((crc >> 16) & 0xff),
    uint8_t((crc >>  8) & 0xff),
    uint8_t((crc >>  0) & 0xff)
  };
  return "\n=" + base64Encode(data);
}

inline const std::string base64Blocks(const std::vector<unsigned char> &data) {
  const std::string base64 = base64Encode(data);
  std::string result;
  for (size_t index = 0; index < base64.size(); index += 64) {
      if (index > 0) {
          result += "\n";
      }
      result += base64.substr(index, 64);
  }
  return result;
}

inline const std::string PEM(const std::string type, ByteBuffer data) {
    return "\n" + fiveDashes + "BEGIN " + type + fiveDashes + "\n\n" +
        base64Blocks(data.byteVector) +
        checksumLine(data.byteVector) +
         "\n" +
        fiveDashes + "END " + type + fiveDashes + "\n";
}
