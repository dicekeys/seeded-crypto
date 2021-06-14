#include "OpenPgpPacket.hpp"
#include "EdDsaPublicPacket.hpp"
#include "SHA1.hpp"

// For EC DH (elliptic curve diffie helman public-key crypto for message confidentiality)
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.6.6


const ByteBuffer encodePublicKeyBytesToEdDsaPointFormat(const ByteBuffer& publicKey) {
  // RFC4880-bis-10 - Section 13.3 - EdDSA Point Format
  // 0x40 indicate compressed format
  ByteBuffer taggedPublicKeyBuffer;
  taggedPublicKeyBuffer.writeByte(0x40);
  taggedPublicKeyBuffer.append(publicKey);
  return taggedPublicKeyBuffer;
}

const ByteBuffer createEdDsaPublicPacketBody(const ByteBuffer& publicKeyInEdDsaPointFormat, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(ALGORITHM_ED_DSA);
  packetBody.writeByte(ALGORITHM_ED_DSA_CURVE_OID_25519.size());
  packetBody.append(ALGORITHM_ED_DSA_CURVE_OID_25519);
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(publicKeyInEdDsaPointFormat));
  return packetBody;
}

const ByteBuffer createEdDsaPublicPacketHashPreimage(const ByteBuffer& EdDsaPublicPacketBody) {
  ByteBuffer preimage;
  preimage.writeByte(0x99);
  preimage.write16Bits(EdDsaPublicPacketBody.size()); // 2-bytes
  preimage.append(EdDsaPublicPacketBody);
  return preimage;
}


// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
// followed by the two-octet packet length, followed by the entire
// Public-Key packet starting with the version field.
const ByteBuffer getPublicKeyFingerprintFromPreImage(const ByteBuffer& preimage) {
  sha1 hash = sha1();
  hash.add(preimage.byteVector.data(), preimage.byteVector.size());
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


EdDsaPublicPacket::EdDsaPublicPacket(
  const ByteBuffer& _publicKeyBytes,
  uint32_t _timestamp
) :
  OpenPgpPacket(pTagPublicPacket),
  publicKeyBytes(_publicKeyBytes),
  publicKeyInEdDsaPointFormat(encodePublicKeyBytesToEdDsaPointFormat(publicKeyBytes)),
  timestamp(_timestamp),
  body(createEdDsaPublicPacketBody(publicKeyInEdDsaPointFormat, timestamp)),
  preimage(createEdDsaPublicPacketHashPreimage(body)),
  fingerprint(getPublicKeyFingerprintFromPreImage(preimage)),
  keyId(getPublicKeyIdFromFingerprint(fingerprint))
{};

const ByteBuffer& EdDsaPublicPacket::getBody() const { return body; }
