#include "OpenPgpPacket.hpp"
#include "PublicKeyPacket.hpp"
#include "SHA1.hpp"

// For EC DH (elliptic curve diffie helman public-key crypto for message confidentiality)
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.6.6


//                 9.2.  ECC Curve OID
//                  The parameter curve OID is an array of octets that define a named
//                  curve.  The table below specifies the exact sequence of bytes for
//                  each named curve referenced in this document:
//                 ...
//                 | 1.3.6.1.4.1.11591.15.1 | 9   | 2B 06 01 04 01  | Ed25519    |
//                 |                        |     | DA 47 0F 01     |            |
//                 ...
//                 The first omitted field is one octet
//                 representing the Object Identifier tag,
//                 and the second omitted field
//                  is the length of the Object Identifier body.
PublicKeyConfiguration edDsaConfiguration(ALGORITHM_ED_DSA, ALGORITHM_ED_DSA_CURVE_OID_25519);
PublicKeyConfiguration ecDhConfiguration(ALGORITHM_EC_DH, ALGORITHM_EC_DH_CURVE_OID_25519);

const ByteBuffer encodePublicKeyBytesToEccCompressedPointFormat(
  const ByteBuffer& publicKeyBytes
) {
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-13.3
  // 13.2.  ECDSA and ECDH Conversion Primitives
  //   For a custom compressed point the content of the MPI is:

  //   B = 40 || x

  //    where x is the x coordinate of the point P encoded to the rules
  //    defined for the specified curve.  This format is used for ECDH keys
  //    based on curves expressed in Montgomery form.

  //    Therefore, the exact size of the MPI payload is [...]
  //    263 for Curve25519.

  // 13.3.  EdDSA Point Format
  //
  //    The EdDSA algorithm defines a specific point compression format.  To
  //    indicate the use of this compression format and to make sure that the
  //    key can be represented in the Multiprecision Integer (MPI) format the
  //    octet string specifying the point is prefixed with the octet 0x40.
  //    This encoding is an extension of the encoding given in [SEC1] which
  //    uses 0x04 to indicate an uncompressed point.
  //
  //    For example, the length of a public key for the curve Ed25519 is 263
  //    bit: 7 bit to represent the 0x40 prefix octet and 32 octets for the
  //    native value of the public key.
  ByteBuffer compressedPointFormat;
  compressedPointFormat.writeByte(0x40);
  compressedPointFormat.append(publicKeyBytes);
  return compressedPointFormat;
}

const ByteBuffer createEdDsaPublicPacketBody(
  const PublicKeyConfiguration& configuration,
  const ByteBuffer& publicKeyInPointFormat,
  uint32_t timestamp
) {
  ByteBuffer packetBody;
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-3.7
  // 5.5.2.  Public-Key Packet Formats
  //
  //  There are three versions of key-material packets.  Version 3 packets
  //  were first generated by PGP version 2.6.  Version 4 keys first
  //  appeared in PGP 5 and are the preferred key version for OpenPGP.
  //
  //  OpenPGP implementations MUST create keys with version 4 format.  V3
  //  keys are deprecated; an implementation MUST NOT generate a V3 key,
  //  but MAY accept it.
  //
  //  A version 4 packet contains:
  //
  //  *  A one-octet version number (4).
  packetBody.writeByte(VERSION_4);
  //  *  A four-octet number denoting the time that the key was created.
  packetBody.write32Bits(timestamp);
  //  *  A one-octet number denoting the public-key algorithm of this key.
  packetBody.writeByte(configuration.algorithm);
  //
  //  *  A series of multiprecision integers comprising the key material.
  //     This is algorithm-specific and described in Section 5.6.
  //         https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-5.6.4
  //        
  //         The public key is this series of values:
  //        
  //          *  a variable-length field containing a curve OID, formatted as
  //             follows:
  //        
  //             -  a one-octet size of the following field; values 0 and 0xFF are
  //                reserved for future extensions,
  packetBody.writeByte(configuration.curve.size());
  //        
  //             -  the octets representing a curve OID, defined in Section 9.2;
  //                 https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-9.2
  packetBody.append(configuration.curve);
  //  [popping back up to 5.6.4]
  //  *  a MPI of an EC point representing a public key.
  packetBody.append(wrapKeyAsMpiFormat(publicKeyInPointFormat));
  return packetBody;
}

const ByteBuffer createEdDsaPublicPacketHashPreimage(const ByteBuffer& publicPacketBody) {
  ByteBuffer preImage;
  // 5.2.4.  Computing Signatures
  // ...
  //  When a V4 signature is made over a key, the hash data starts with the
  //  octet 0x99, followed by a two-octet length of the key, and then body
  //  of the key packet;
  preImage.writeByte(START_V4_SIGNATURE_PREIMAGE); // 0x99
  preImage.write16Bits(publicPacketBody.size()); // 2 octets
  preImage.append(publicPacketBody);
  return preImage;
}


// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
// followed by the two-octet packet length, followed by the entire
// Public-Key packet starting with the version field.
const ByteBuffer getPublicKeyFingerprintFromPreImage(const ByteBuffer& preImage) {
  sha1 hash = sha1();
  hash.add(preImage.byteVector.data(), preImage.byteVector.size());
  hash.finalize();
  ByteBuffer hashBuffer;
  // Write a word at a time to ensure the hash has the correct byte ordering.
  for (uint32_t word = 0; word < 5; word++) {
    hashBuffer.write32Bits(hash.state[word]);
  }
  return hashBuffer;
}

// The Key ID is the low-order 64 bits of the fingerprint.
const ByteBuffer getPublicKeyIdFromFingerprint(const ByteBuffer& publicKeyFingerprint) {
  return publicKeyFingerprint.slice(publicKeyFingerprint.size() - 8, 8);
}


PublicKeyPacket::PublicKeyPacket(
  const PublicKeyConfiguration& configuration,
  const ByteBuffer& _publicKeyBytes,
  uint32_t _timestamp
) :
  OpenPgpPacket(PTAG_PUBLIC),
  publicKeyBytes(_publicKeyBytes),
  publicKeyInEdDsaPointFormat(encodePublicKeyBytesToEccCompressedPointFormat(publicKeyBytes)),
  timestamp(_timestamp),
  body(createEdDsaPublicPacketBody(configuration, publicKeyInEdDsaPointFormat, timestamp)),
  preImage(createEdDsaPublicPacketHashPreimage(body)),
  fingerprint(getPublicKeyFingerprintFromPreImage(preImage)),
  keyId(getPublicKeyIdFromFingerprint(fingerprint))
{};

const ByteBuffer& PublicKeyPacket::getBody() const { return body; }

EdDsaPublicPacket::EdDsaPublicPacket(
  const ByteBuffer& _publicKeyBytes,
  uint32_t _timestamp
) : PublicKeyPacket(edDsaConfiguration, _publicKeyBytes, _timestamp) {}

EcDhPublicPacket::EcDhPublicPacket(
  const ByteBuffer& _publicKeyBytes,
  uint32_t _timestamp
) : PublicKeyPacket(ecDhConfiguration, _publicKeyBytes, _timestamp) {}
