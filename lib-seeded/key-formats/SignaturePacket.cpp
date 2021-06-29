#include <sodium.h>
#include "../sodium-buffer.hpp"
#include "OpenPgpPacket.hpp"
#include "SignaturePacket.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "UserPacket.hpp"

const ByteBuffer createSubpacket(ubyte type, const ByteBuffer& subpacketBodyBuffer) {
  ByteBuffer packet;
  // RFC2440 Section 4.2.2
  // Should follow the spec as described in RFC4880-bis-10 - Section 5.2.3.1.
  // Hardcoded to one byte as 191 length is enough for our use case.
  packet.writeByte(subpacketBodyBuffer.size() + 1); // + 1 is the type byte
  packet.writeByte(type);
  packet.append(subpacketBodyBuffer);
  return packet;
}
const ByteBuffer createSubpacket(ubyte type, std::vector<ubyte>& subpacketBodyVector) {
  return createSubpacket(type, ByteBuffer(subpacketBodyVector));
}

const ByteBuffer createSubpacketsToBeSigned(const ByteBuffer & pubicKeyFingerprint, uint32_t timestamp, const KeyConfiguration &keyConfiguration) {
  ByteBuffer signedSubpackets;
  {
    // Issuer Fingerprint (0x21)
    ByteBuffer subpacket;
    subpacket.writeByte(keyConfiguration.version);
    subpacket.append(pubicKeyFingerprint);
    signedSubpackets.append(createSubpacket(0x21 /* issuer */, subpacket));
  } {
    // Signature Creation Time (0x2)
    ByteBuffer subpacket;
    subpacket.write32Bits(timestamp);
    signedSubpackets.append(createSubpacket(0x02, subpacket));
  }  
  // Key Flags (0x1b)
  signedSubpackets.append(createSubpacket(0x1b, keyConfiguration.keyFlags));  
  // Preferred Symmetric Algorithms (0xb)
  signedSubpackets.append(createSubpacket(0x0b, keyConfiguration.preferredSymmetricAlgorithms));
  // Preferred Hash Algorithms (0x15)
  signedSubpackets.append(createSubpacket(0x15, keyConfiguration.preferredHashAlgorithms));
  // Preferred Compression Algorithms (0x16)
  signedSubpackets.append(createSubpacket(0x16, keyConfiguration.preferredCompressionAlgorithms));
  // Features (0x1e)
  signedSubpackets.append(createSubpacket(0x1e, keyConfiguration.features));
  // Key Server Preferences (0x17)
  signedSubpackets.append(createSubpacket(0x17, keyConfiguration.keyServerPreferences));
  return signedSubpackets;
}

const ByteBuffer createSignaturePacketBodyIncludedInSignatureHash(
  const ubyte signatureType,
  const ByteBuffer& pubicKeyFingerprint,
  uint32_t timestamp,
  const KeyConfiguration &keyConfiguration
) {
    ByteBuffer packetBody;
    // |  5.2.3.  Version 4 and 5 Signature Packet Formats
    // |    The body of a V4 or V5 Signature packet contains:

    // |  *  One-octet version number.  This is 4 for V4 signatures and 5 for
    // |      V5 signatures.
    packetBody.writeByte(keyConfiguration.version);

    // |  *  One-octet signature type.
    // |        5.2.1.  Signature Types
    // |        ...
    // |        0x13: Positive certification of a User ID and Public - Key packet.
    // |              The issuer of this certification has done substantial verification
    // |              of the claim of identity.Most OpenPGP implementations make their
    // |              "key signatures" as 0x10 certifications.Some implementations can
    // |              issue 0x11 - 0x13 certifications, but few differentiate between the
    // |              types.
    packetBody.writeByte(signatureType);

    // |  *  One-octet public-key algorithm.
    packetBody.writeByte(ALGORITHM_ED_DSA);
    
    // |  *  One-octet hash algorithm.
    packetBody.writeByte(ALGORITHM_HASH_SHA_256);

    // |   *  Two-octet scalar octet count for following hashed subpacket data.
    // |      Note that this is the length in octets of all of the hashed
    // |      subpackets; a pointer incremented by this number will skip over
    // |      the hashed subpackets.

    // |   *  Hashed subpacket data set (zero or more subpackets).
    ByteBuffer hashedSubpackets = createSubpacketsToBeSigned(pubicKeyFingerprint, timestamp, keyConfiguration);
    packetBody.write16Bits(hashedSubpackets.size()); // hashed_area_len
    packetBody.append(hashedSubpackets);

    return packetBody;
}


const ByteBuffer createSignaturePacketHashPreImage(
  const KeyConfiguration &keyConfiguration,
  const PublicKeyPacket& publicKeyPacket,
  const UserPacket& userPacket,
  const ByteBuffer& signaturePacketBodyIncludedInHash
) {
  ByteBuffer preImage;
  // | 5.2.3.  Version 4 and 5 Signature Packet Formats
  // | ...
  // |  The concatenation of the data being signed and the signature data
  // |  from the version number through the hashed subpacket data (inclusive)
  // |  is hashed.
  preImage.append(publicKeyPacket.preImage);
  preImage.append(userPacket.getPreImage());
  preImage.append(signaturePacketBodyIncludedInHash);
  // | 5.2.4. Computing Signatures
  // | (the above function takes us to the end of the line that includes "the hashed subpacket body")
  // | ...
  // [V4 ONLY] |  -  the two octets 0x04 and 0xFF
  // [V5 ONLY| |  -  the two octets 0x05 and 0xFF,
    preImage.writeByte(keyConfiguration.version);
    preImage.writeByte(0xff);
  if (keyConfiguration.version > VERSION_4) {
    // Buried in 5.2.4 of the spec, in a long list of items that go in V4 and V5 signatures,
    // is the fact that V4 
    // The length field is documented as 4 octets for V4 signatures and
    // 8 octets for V5 signatures.
    // |  -  a [four (V4)/eight (V5)-octet big-endian number that is the length of the
    // |     hashed data from the Signature packet stopping right before the
    // |     [0x04 0xff if V4, 0x05 0xff if V5] octets.

    // The first 4 octets of an 8-byte counter will be zero because we are not
    // supporting 4GB+ files.
    preImage.write32Bits(0);
  }
  preImage.write32Bits(signaturePacketBodyIncludedInHash.size());
  return preImage;
}

const ByteBuffer createSignatureHashSHA256(
  const ByteBuffer &preImage
) {
  ByteBuffer sha256Hash(crypto_hash_sha256_BYTES);
  crypto_hash_sha256(sha256Hash.byteVector.data(), preImage.byteVector.data(), preImage.byteVector.size());
  return sha256Hash;
}

const ByteBuffer createSignature(
  const SigningKey sk,
  const ByteBuffer& signatureHashSha256
) {
  ByteBuffer signatureBody;
  // 5.2.3.  Version 4 and 5 Signature Packet Formats
  // ...   The high 16
  //  bits (first two octets) of the hash are included in the Signature
  //  packet to provide a way to reject some invalid signatures without
  //  performing a signature verification.

  signatureBody.writeByte(signatureHashSha256.byteVector[0]);
  signatureBody.writeByte(signatureHashSha256.byteVector[1]);

  // Use libsodium directly to create a raw signature
  ByteBuffer signature(crypto_sign_BYTES);
  crypto_sign_detached(signature.byteVector.data(), NULL, signatureHashSha256.byteVector.data(), crypto_hash_sha256_BYTES, sk.signingKeyBytes.data);

  // 5.2.3...
  // Algorithm-Specific Fields for EdDSA signatures:
  //
  //       -  MPI of an EC point r.
  //
  //       -  EdDSA value s, in MPI, in the little endian representation.
  //
  //    The format of R and S for use with EdDSA is described in [RFC8032].
  signatureBody.append(wrapKeyAsMpiFormat(signature.slice(0, 32)));
  signatureBody.append(wrapKeyAsMpiFormat(signature.slice(32, 32)));
  return signatureBody;
}

const ByteBuffer createUnhashedSubpacketsWithSizePrefix(const ByteBuffer& keyId) {
  ByteBuffer unhashedSubpackets;
  {
    // Issuer 0x10 (keyId which is last 8 bytes of SHA256 of public key packet body)
    unhashedSubpackets.append(createSubpacket(0x10 /* issuer */, keyId));
  }
  ByteBuffer unhashedSubpacketsWithSizePrefix;
  unhashedSubpacketsWithSizePrefix.write16Bits(unhashedSubpackets.size()); // unhashed_area_len
  unhashedSubpacketsWithSizePrefix.append(unhashedSubpackets);
  return unhashedSubpacketsWithSizePrefix;
}

const ByteBuffer createSignaturePacketBody(
  const ByteBuffer packetBodyIncludedInSignatureHash,
  const ByteBuffer signature,
  const ByteBuffer unhashedSubpacketsWithSizePrefix
) {
  ByteBuffer packetBody;
  packetBody.append(packetBodyIncludedInSignatureHash);
  packetBody.append(unhashedSubpacketsWithSizePrefix);
  packetBody.append(signature);
  return packetBody;
}

SignaturePacket::SignaturePacket(
  const ubyte _signatureType,
  const SigningKey& signingKey,
  const UserPacket& userPacket,
  const PublicKeyPacket& publicKeyPacket,
  uint32_t _timestamp
) :
  OpenPgpPacket(PTAG_SIGNATURE),
  signatureType(_signatureType),
  timestamp(_timestamp),
  packetBodyIncludedInSignatureHash(createSignaturePacketBodyIncludedInSignatureHash(_signatureType, publicKeyPacket.fingerprint, _timestamp, publicKeyPacket.keyConfiguration)),
  signatureHashPreImage(createSignaturePacketHashPreImage(publicKeyPacket.keyConfiguration, publicKeyPacket, userPacket, packetBodyIncludedInSignatureHash)),
  signatureHashSha256(createSignatureHashSHA256(signatureHashPreImage)),
  signature(createSignature(signingKey, signatureHashSha256)),
  unhashedSubpacketsWithSizePrefix(createUnhashedSubpacketsWithSizePrefix(publicKeyPacket.keyId)),
  body(createSignaturePacketBody(packetBodyIncludedInSignatureHash, signature, unhashedSubpacketsWithSizePrefix))
{}

const ByteBuffer& SignaturePacket::getBody() const { return body; };
