#include <vector>
#include <string>
#include "ByteBuffer.hpp"
#include "Packet.hpp"

// draft-ietf-openpgp-rfc4880bis-09, Section 4.2.2
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09
inline std::vector<uint8_t> encodeOpenPgpPacketLength(size_t length) {
  if (length <= 191) {
    // 4.2.2.1
    return std::vector<int8_t>{ uint8_t(length) };
  } else if (length < 8383) {
    // ((1st_octet - 192) << 8) + (2nd_octet) + 192
    const size_t lengthMinus192 = length - 192;
    const uint8_t highByte = 192 + uint8_t(lengthMinus192 >> 8) & 0xff);
    const uint8_t lowByte = lengthMinus192 & 0xff;    
    return std::vector<int8_t>{ highByte, lowByte };
  } else {
    // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
    //           (4th_octet << 8)  | 5th_octet
    return std::vector<int8_t> { 
      0xff,
      uint8_t( (length >> 24) & 0xff),
      uint8_t( (length >> 16) & 0xff),
      uint8_t( (length >>  8) & 0xff),
      uint8_t( (length      ) & 0xff),
    };
  }
}


const uint16_t numberOfConsecutive0BitsAtStartOfByteVector(const std::vector<uint8_t> &byteVector) {
  uint16_t numberOfConsecutive0Bits = 0;
  const auto bytes = byteVector.size();
  for (size_t byteIndex = 0; byteIndex < bytes; byteIndex++) {
    uint8_t byte = byteVector[byteIndex];
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      uint8_t bit = (byte >> (7 - bitIndex)) & 1;
      if (bit == 1) {
        return numberOfConsecutive0Bits;
      } else {
        numberOfConsecutive0Bits++;
      }
    }
  }
  return numberOfConsecutive0Bits;
}

const ByteBuffer wrapKeyWithLengthPrefixAndTrim(const ByteBuffer &value) {
  ByteBuffer wrappedKey;
  uint16_t num0BitsAtStart = numberOfConsecutive0BitsAtStartOfByteVector(value.byteVector);
  uint16_t numberOf0BytesToSkipOver = num0BitsAtStart / 8;
  uint16_t sizeInBits = (value.size() * 8) - num0BitsAtStart; 
  wrappedKey.write16Bits(sizeInBits);
  wrappedKey.append(value, numberOf0BytesToSkipOver);
  return wrappedKey;
}

// Packet format specified in
/**
 * @brief Encode an OpenPGP packet as specified in RFC4880bis Section 4.0
 * https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-4
 * 
 * @param packetTag One-byte packet tag specified in Section 4.2 identifying the type
 * of packet.
 * @param packetBodyBuffer The body of the packet as a ByteBuffer of specified length.
 * @return const ByteBuffer The packet including length information that allows
 * the reader to determien the packet length. 
 */
const ByteBuffer createOpenPgpPacket(uint8_t packetTag, const ByteBuffer &packetBodyBuffer) {
  ByteBuffer packet;
  https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-4.3
  packet.writeByte(packetTag);
  // RFC2440 Section 4.2.
  // Should follow the spec as described in RFC4880-bis-10 - Section 4.2.
  packet.append(encodeOpenPgpPacketLength(packetBodyBuffer.size()));
  packet.append(packetBodyBuffer);
  return packet;
}
