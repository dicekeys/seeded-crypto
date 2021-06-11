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

const uint16_t numberOfConsecutive0BitsAtStartOfByteVector(const std::vector<uint8_t> &byteVector);

const ByteBuffer wrapKeyWithLengthPrefixAndTrim(const ByteBuffer &value);

const ByteBuffer createPacket(uint8_t type, const ByteBuffer &packetBodyBuffer);