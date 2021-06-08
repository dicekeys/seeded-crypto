#pragma once

#include "Packet.hpp""
#include "SHA1.hpp"

const ByteBuffer taggedPublicKey(const ByteBuffer &publicKey) {
  // RFC4880-bis-10 - Section 13.3 - EdDSA Point Format
  // 0x40 indicate compressed format
  // Kotlin:      val taggedPublicKey = byteArrayOf(0x40) + publicKey
  ByteBuffer taggedPublicKeyBuffer;
  taggedPublicKeyBuffer.writeByte(0x40);
  taggedPublicKeyBuffer.append(publicKey);
  return taggedPublicKeyBuffer;
}

const ByteBuffer createPublicPacket(const ByteBuffer &publicKey, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(Ed25519Algorithm);
  packetBody.writeByte(Ed25519CurveOid.size());
  packetBody.append(Ed25519CurveOid);
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKey)));
  return createPacket(pTagPublicPacket, packetBody);
}


// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
// followed by the two-octet packet length, followed by the entire
// Public-Key packet starting with the version field.  The Key ID is the
// low-order 64 bits of the fingerprint.
const ByteBuffer getPublicKeyFingerprint(const ByteBuffer &publicKeyPacket) {
  ByteBuffer preimage;
  preimage.writeByte(0x99);
  preimage.write16Bits(publicKeyPacket.size());
  preimage.append(publicKeyPacket);
  sha1 hash = sha1();
  hash.add(preimage.byteVector.data(), preimage.byteVector.size());
  hash.finalize();
  return ByteBuffer(SHA1_HASH_LENGTH_IN_BYTES, (uint8_t*) hash.state);
}


const ByteBuffer getPublicKeyId(const ByteBuffer &publicKeyFingerprint) {
  return publicKeyFingerprint.slice(publicKeyFingerprint.size() - 8, 8);
}

