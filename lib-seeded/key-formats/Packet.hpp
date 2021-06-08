#pragma once

#include <vector>
#include <string>
#include "ByteBuffer.hpp"

const size_t  SHA1_HASH_LENGTH_IN_BYTES = 20; // 160 bits
const uint8_t s2kUsage = 0x00;
const uint8_t pTagSignaturePacket = 0x88;
const uint8_t pTagPublicPacket = 0x98;
const uint8_t pTagSecretPacket = 0x94;
const uint8_t pTagUserIdPacket = 0xb4;
const uint8_t Version = 0x04;
const uint8_t Sha256Algorithm = 0x08; // RFC4880-bis-10 - Section 9.5 - 08 - SHA2-256 [FIPS180]
const uint8_t Ed25519Algorithm = 0x16; // RFC4880-bis-10 - Section 9.1 - 22 (0x16) - EdDSA [RFC8032]
const std::vector<uint8_t> Ed25519CurveOid = {0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID

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
  // RFC2440 Section 4.2.2
  // Should follow the spec as described in RFC4880-bis-10 - Section 5.2.3.1.
  // Hardcoded to one byte as 191 length is enough for our use case.
  packet.writeByte(packetBodyBuffer.size());
  packet.append(packetBodyBuffer);
  return packet;
}

