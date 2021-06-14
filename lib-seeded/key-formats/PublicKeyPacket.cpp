#include "PublicKeyPacket.hpp"
#include "Packet.hpp"
#include "SHA1.hpp"

// For EC DH (elliptic curve diffie helman public-key crypto for message confidentiality)
// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.6.6



class PublicKeyPacket : Packet {
  const ByteBuffer& publicKeyBytes;
  const uint32_t timestamp;
  PublicKeyPacker(
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp
  ) {
    super(pTagPublicPacket);
    publicKeyBytes = _publicKeyBytes;
    timestamp = _timestamp;
  }

  const ByteBuffer taggedPublicKey() {
    // RFC4880-bis-10 - Section 13.3 - EdDSA Point Format
    // 0x40 indicate compressed format
    // Kotlin:      val taggedPublicKey = byteArrayOf(0x40) + publicKey
    ByteBuffer taggedPublicKeyBuffer;
    taggedPublicKeyBuffer.writeByte(0x40);
    taggedPublicKeyBuffer.append(publicKeyBytes);
    return taggedPublicKeyBuffer;
  }

  virtual void writeBody(ByteBuffer &outputBuffer) {
    outputBuffer.writeByte(Version);
    outputBuffer.write32Bits(timestamp);
    outputBuffer.writeByte(ALGORITHM_ED_DSA);
    outputBuffer.writeByte(ALGORITHM_ED_DSA_CURVE_OID_25519.size());
    outputBuffer.append(ALGORITHM_ED_DSA_CURVE_OID_25519);
    outputBuffer.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKeyBytes)));
  }

  override writePreImage(ByteBuffer &outputBuffer) {
    preimage.writeByte(0x99);
    ByteBuffer body = getBody();
    preimage.write16Bits(body.size()); // 2-bytes
    preimage.append(body);
  }

}


// For ED_DSA
/// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis-10#section-5.6.5
const ByteBuffer createPublicKeyPacketBody(const ByteBuffer& publicKeyBytes, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(ALGORITHM_ED_DSA);
  packetBody.writeByte(ALGORITHM_ED_DSA_CURVE_OID_25519.size());
  packetBody.append(ALGORITHM_ED_DSA_CURVE_OID_25519);
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKeyBytes)));
  return packetBody;
}


const ByteBuffer createPublicKeyPacketHashPreimage(const ByteBuffer& publicKeyPacketBody) {
  ByteBuffer preimage;
  preimage.writeByte(0x99);
  preimage.write16Bits(publicKeyPacketBody.size()); // 2-bytes
  preimage.append(publicKeyPacketBody);
  return preimage;
}

const ByteBuffer createPublicKeyPacket(const ByteBuffer& publicKeyPacketBody) {
  return createOpenPgpPacket(pTagPublicPacket, publicKeyPacketBody);
}

const ByteBuffer createPublicKeyPacket(const ByteBuffer &publicKeyBytes, uint32_t timestamp) {
  return createPublicKeyPacket(createPublicKeyPacketBody(publicKeyBytes, timestamp));
}


// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
// followed by the two-octet packet length, followed by the entire
// Public-Key packet starting with the version field.
const ByteBuffer getPublicKeyFingerprint(const ByteBuffer &publicKeyPacketBody) {
  ByteBuffer preimage;
  preimage.writeByte(0x99);
  // body is the packet after the ptag byte and the size byte,
  // so subtract that two byte prefix from what's written
  preimage.write16Bits(publicKeyPacketBody.size());
  preimage.append(publicKeyPacketBody);
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
const ByteBuffer getPublicKeyIdFromFingerprint(const ByteBuffer &publicKeyFingerprint) {
  return publicKeyFingerprint.slice(publicKeyFingerprint.size() - 8, 8);
}

const ByteBuffer getPublicKeyIdFromPublicKeyPacketBody(const ByteBuffer& publicKeyPacketBody) {
  return getPublicKeyIdFromFingerprint(getPublicKeyFingerprint(publicKeyPacketBody));
}