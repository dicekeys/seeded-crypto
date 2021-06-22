#include <vector>
#include <string>
#include "ByteBuffer.hpp"
#include "OpenPgpPacket.hpp"

// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-4.2.2
// 4.2.2.  New Format Packet Lengths
//
//    New format packets have four possible ways of encoding length:
//
//    1.  A one-octet Body Length header encodes packet lengths of up to
//        191 octets.
//
//    2.  A two-octet Body Length header encodes packet lengths of 192 to
//        8383 octets.
//
//    3.  A five-octet Body Length header encodes packet lengths of up to
//        4,294,967,295 (0xFFFFFFFF) octets in length.  (This actually
//        encodes a four-octet scalar number.)
const std::vector<ubyte> encodeOpenPgpPacketLength(size_t length) {
  if (length <= 191) {
    // 4.2.2.1.  One-Octet Lengths
    //
    // A one-octet Body Length header encodes a length of 0 to 191 octets.
    // This type of length header is recognized because the one octet value
    // is less than 192.  The body length is equal to:
    //
    // bodyLen = 1st_octet;
    return std::vector<ubyte>{ ubyte(length) };
  } else if (length < 8383) {
    // 4.2.2.2.  Two-Octet Lengths
    //
    // A two-octet Body Length header encodes a length of 192 to 8383
    // octets.  It is recognized because its first octet is in the range 192
    // to 223.  The body length is equal to:
    //
    // bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192
    const size_t lengthMinus192 = length - 192;
    const ubyte highByte = 192 + ubyte( (lengthMinus192 >> 8) & 0xff);
    const ubyte lowByte = lengthMinus192 & 0xff;    
    return std::vector<ubyte>{ highByte, lowByte };
  } else {
    // 4.2.2.3.  Five-Octet Lengths
    //
    // A five-octet Body Length header consists of a single octet holding
    // the value 255, followed by a four-octet scalar.  The body length is
    // equal to:
    //
    // bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
    //           (4th_octet << 8)  | 5th_octet
    return std::vector<ubyte> { 
      0xff,
      ubyte( (length >> 24) & 0xff),
      ubyte( (length >> 16) & 0xff),
      ubyte( (length >>  8) & 0xff),
      ubyte( (length      ) & 0xff),
    };
  }
}

const uint16_t numberOfConsecutive0BitsAtStartOfByteVector(const std::vector<ubyte> &byteVector) {
  uint16_t numberOfConsecutive0Bits = 0;
  const auto bytes = byteVector.size();
  for (size_t byteIndex = 0; byteIndex < bytes; byteIndex++) {
    ubyte byte = byteVector[byteIndex];
    for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
      ubyte bit = (byte >> (7 - bitIndex)) & 1;
      if (bit == 1) {
        return numberOfConsecutive0Bits;
      } else {
        numberOfConsecutive0Bits++;
      }
    }
  }
  return numberOfConsecutive0Bits;
}

const ByteBuffer wrapKeyAsMpiFormat(const ByteBuffer &value) {
  uint16_t num0BitsAtStart = numberOfConsecutive0BitsAtStartOfByteVector(value.byteVector);
  uint16_t numberOf0BytesToSkipOver = num0BitsAtStart / 8;
  uint16_t lengthInBits = (value.size() * 8) - num0BitsAtStart; 
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-3.2
  // 3.2.  Multiprecision Integers

  //  Multiprecision integers (also called MPIs) are unsigned integers used
  //  to hold large integers such as the ones used in cryptographic
  //  calculations.

  //  An MPI consists of two pieces: a two-octet scalar that is the length
  //  of the MPI in bits followed by a string of octets that contain the
  //  actual integer.
  ByteBuffer mpiWrappedKey;
  mpiWrappedKey.write16Bits(lengthInBits);
  mpiWrappedKey.append(value, numberOf0BytesToSkipOver);
  return mpiWrappedKey;
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
const ByteBuffer createOpenPgpPacket(ubyte packetTag, const ByteBuffer &packetBodyBuffer) {
  ByteBuffer packet;
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-09#section-4.3
  packet.writeByte(packetTag);
  // RFC2440 Section 4.2.
  // Should follow the spec as described in RFC4880-bis-10 - Section 4.2.
  packet.append(encodeOpenPgpPacketLength(packetBodyBuffer.size()));
  packet.append(packetBodyBuffer);
  return packet;
}

ByteBuffer OpenPgpPacket::encode() const {
  ByteBuffer packet;
  ByteBuffer body = getBody();
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
  //  New format packets contain:
  //
  //    Bits 5-0 -- packet tag

  packet.writeByte(packetTag);
  // RFC2440 Section 4.2.
  // Should follow the spec as described in RFC4880-bis-10 - Section 4.2.
  packet.append(encodeOpenPgpPacketLength(body.size()));
  packet.append(body);
  return packet;
};
