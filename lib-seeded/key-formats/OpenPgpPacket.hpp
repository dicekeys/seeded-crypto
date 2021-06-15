#pragma once

#include <vector>
#include <string>
#include "ByteBuffer.hpp"

const uint8_t VERSION_4 = 0x04;
const uint8_t VERSION_5 = 0x05;

const size_t  VERSION_4_FINGERPRINT_LENGTH_IN_BYTES_DUE_TO_USE_OF_SHA1 = 20; // 160 bits
const size_t  VERSION_5_FINGERPRINT_LENGTH_IN_BYTES = 32; // 160 bits

// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-3.7.1.1
  //  This directly hashes the string to produce the key data.  See below
  //  for how this hashing is done.

  //    Octet 0:        0x00
  //    Octet 1:        hash algorithm
const uint8_t SECRET_KEY_ENCRYPTION_OFF = 0x00;
const uint8_t SECRET_KEY_ENCRYPTION_ON = 0xff; // 0xfe also works

  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-4.2
  
  //  The first octet of the packet header is called the "Packet Tag".  It
  //  determines the format of the header and denotes the packet contents.
  //  The remainder of the packet header is the length of the packet.

  //  Note that the most significant bit is the leftmost bit, called bit 7.
  //  A mask for this bit is 0x80 in hexadecimal.

  //         ┌───────────────┐
  //    PTag │7 6 5 4 3 2 1 0│
  //         └───────────────┘
  //    Bit 7 -- Always one
  //    Bit 6 -- New packet format if set

  //  PGP 2.6.x only uses old format packets.  Thus, software that
  //  interoperates with those versions of PGP must only use old format
  //  packets.  If interoperability is not an issue, the new packet format
  //  is RECOMMENDED.  Note that old format packets have four bits of
  //  packet tags, and new format packets have six; some features cannot be
  //  used and still be backward-compatible.

  //  Also note that packets with a tag greater than or equal to 16 MUST
  //  use new format packets.  The old format packets can only express tags
  //  less than or equal to 15.

  //  Old format packets contain:
  //
  //    Bits 5-2 -- packet tag
  //    Bits 1-0 -- length-type
  //

// Coder's (Stuart's) note: These all have the high bit set and length type 0,
// the formula is 0x80 | ((packetType) << 2) = 128 + (packetType * 4)
inline uint8_t pTagOctetOldFormat(uint8_t tag) {
  return 0x80 | (tag << 2);
}
// | 2 | Signature Packet |
const uint8_t PTAG_SIGNATURE = pTagOctetOldFormat(2); // 0x88,  type 2: 0x80 | ((2) << 2) = 0x88
// | 5 | Secret - Key Packet |
const uint8_t PTAG_SECRET = pTagOctetOldFormat(5); // 0x94, type 5: 0x80 | ((5) << 2)
// | 6 | Public - Key Packet |
const uint8_t PTAG_PUBLIC = pTagOctetOldFormat(6); //  0x98, type 6: 0x80 | ((6) << 2) 
// | 13 | User ID Packet |
const uint8_t PTAG_USER_ID = pTagOctetOldFormat(13); // 0xb4, type 13: 0x80 | ((0xe) << 2) = 1000000 | 00110100 = 10110100 = 0xb4
// | 17 | User Attribute Packet |



const uint8_t START_V4_SIGNATURE_PREIMAGE = 0x99;

const uint8_t ALGORITHM_HASH_SHA_256 = 0x08; // RFC4880-bis-10 - Section 9.5 - 08 - SHA2-256 [FIPS180]

const uint8_t ALGORITHM_EC_DH = 0x12; // RFC4880-bis-10 - Section 9.1 - 18 (0x12) - ECDH [RFC8032]
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-9.2
const std::vector<uint8_t> ALGORITHM_EC_DH_CURVE_OID_25519 = {0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID


const uint8_t ALGORITHM_ED_DSA = 0x16; // RFC4880-bis-10 - Section 9.1 - 22 (0x16) - EdDSA [RFC8032]
const std::vector<uint8_t> ALGORITHM_ED_DSA_CURVE_OID_25519 = {0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID

const uint16_t numberOfConsecutive0BitsAtStartOfByteVector(const std::vector<uint8_t> &byteVector);

const ByteBuffer wrapKeyAsMpiFormat(const ByteBuffer &value);

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


class OpenPgpPacket {
public:
  uint8_t packetTag;

  OpenPgpPacket(uint8_t _packetTag) {
    packetTag = _packetTag;
  }

  virtual const ByteBuffer& getBody() const = 0;
  ByteBuffer encode() const;
};
