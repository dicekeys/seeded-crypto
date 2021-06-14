#pragma once

#include <vector>
#include <string>
#include "ByteBuffer.hpp"

namespace Version {
  const uint8_t VERSION_4 = 0x04;
  const uint8_t VERSION_5 = 0x04;
}




const size_t  SHA1_HASH_LENGTH_IN_BYTES = 20; // 160 bits

const uint8_t s2kUsage = 0x00;
const uint8_t pTagSignaturePacket = 0x88;
const uint8_t pTagPublicPacket = 0x98;
const uint8_t pTagSecretPacket = 0x94;
const uint8_t pTagUserIdPacket = 0xb4;
const uint8_t Version = 0x04;

const uint8_t ALGORITHM_HASH_SHA_256 = 0x08; // RFC4880-bis-10 - Section 9.5 - 08 - SHA2-256 [FIPS180]



const uint8_t ALGORITHM_EC_DH = 0x12; // RFC4880-bis-10 - Section 9.1 - 18 (0x12) - ECDH [RFC8032]
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-9.2
const std::vector<uint8_t> ALGORITHM_EC_DH_CURVE_OID_25519 = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID


const uint8_t ALGORITHM_ED_DSA = 0x16; // RFC4880-bis-10 - Section 9.1 - 22 (0x16) - EdDSA [RFC8032]
const std::vector<uint8_t> ALGORITHM_ED_DSA_CURVE_OID_25519 = {0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID

const uint16_t numberOfConsecutive0BitsAtStartOfByteVector(const std::vector<uint8_t> &byteVector);

const ByteBuffer wrapKeyWithLengthPrefixAndTrim(const ByteBuffer &value);

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
const ByteBuffer createOpenPgpPacket(uint8_t packetTag, const ByteBuffer &packetBodyBuffer);


abstract class OpenPgpPacket {
  const uint8_t packetTag,
  
  OpenPgpPacket(uint8_t _packetTag) {
    packetTag = _packetTag;
    packetBodyBuffer = _packetBodyBuffer;
  }

  virtual void writeBody(ByteBuffer &outputBuffer);

  virtual void writePreImage(ByteBuffer &outputBuffer) {
    writeBody();
  }

  ByteBuffer getBody() {
    ByteBuffer outputBuffer;
    writeBody(outputBuffer);
    return outputBuffer;
  }

  ByteBuffer getPreimage() {
    ByteBuffer outputBuffer;
    writeBody(outputBuffer);
    return outputBuffer;
  };

  ByteBuffer encode() {
    ByteBuffer packet; 
    ByteBuffer packet;
    https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-4.3
    packet.writeByte(packetTag);
    // RFC2440 Section 4.2.
    // Should follow the spec as described in RFC4880-bis-10 - Section 4.2.
    packet.append(encodeOpenPgpPacketLength(packetBodyBuffer.size()));
    packet.append(getBody());
    return packet;
  };
}