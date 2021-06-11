#include <vector>
#include <string>
#include "ByteBuffer.hpp"
#include "Packet.hpp"

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

const ByteBuffer createPacket(uint8_t type, const ByteBuffer &packetBodyBuffer) {
  ByteBuffer packet;
  packet.writeByte(type);
  // RFC2440 Section 4.2.
  // Should follow the spec as described in RFC4880-bis-10 - Section 4.2.
  packet.writeByte(packetBodyBuffer.size());
  packet.append(packetBodyBuffer);
  return packet;
}
