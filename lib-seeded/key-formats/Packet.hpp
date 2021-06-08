#pragma once

#include <vector>
#include <string>
#include "ByteBuffer.hpp"
#include "SHA1.hpp"
#include "sodium.h"

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
}

const ByteBuffer wrapKeyWithLengthPrefixAndTrim(const ByteBuffer &value) {
  ByteBuffer wrappedKey;
  uint16_t num0BitsAtStart = numberOfConsecutive0BitsAtStartOfByteVector(value.byteVector);
  uint16_t numberOf0BytesToSkipOver = num0BitsAtStart / 8;
  uint16_t sizeInBits = (value.size() * 8) - num0BitsAtStart; 
  wrappedKey.write16Bits(sizeInBits);
  wrappedKey.append(value, numberOf0BytesToSkipOver);
  return wrappedKey;
};

const ByteBuffer createPacket(uint8_t type, const ByteBuffer &packetBodyBuffer) {
  ByteBuffer packet;
  packet.writeByte(type);
  // RFC2440 Section 4.2.2
  // Should follow the spec as described in RFC4880-bis-10 - Section 5.2.3.1.
  // Hardcoded to one byte as 191 length is enough for our use case.
  packet.writeByte(packetBodyBuffer.size());
  packet.append(packetBodyBuffer);
  return packet;
};

const ByteBuffer taggedPublicKey(const ByteBuffer &publicKey) {
  // RFC4880-bis-10 - Section 13.3 - EdDSA Point Format
  // 0x40 indicate compressed format
  // Kotlin:      val taggedPublicKey = byteArrayOf(0x40) + publicKey
  ByteBuffer taggedPublicKeyBuffer;
  taggedPublicKeyBuffer.writeByte(0x40);
  taggedPublicKeyBuffer.append(publicKey);
  return taggedPublicKeyBuffer;
};

const ByteBuffer createPublicPacket(const ByteBuffer &publicKey, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(Ed25519Algorithm);
  packetBody.writeByte(Ed25519CurveOid.size());
  packetBody.append(Ed25519CurveOid);
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKey)));
  return createPacket(pTagPublicPacket, packetBody);
};

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey) {
  uint16_t checksum = 0;
  for (size_t i = 0; i < wrappedSecretKey.byteVector.size(); i ++) {
    const uint8_t byte = wrappedSecretKey.byteVector[i];
    checksum += byte;
  }
  return checksum;
}

const ByteBuffer createSecretPacket(const ByteBuffer &secretKey, ByteBuffer &publicKey, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(Ed25519Algorithm);
  packetBody.writeByte(Ed25519CurveOid.size());
  packetBody.append(Ed25519CurveOid);

  packetBody.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKey)));

  packetBody.writeByte(s2kUsage);

  const ByteBuffer wrappedSecretKey = wrapKeyWithLengthPrefixAndTrim(secretKey);
  packetBody.append(wrappedSecretKey);
  packetBody.write16Bits(calculateCheckSumOfWrappedSecretKey(wrappedSecretKey));
  return createPacket(pTagSecretPacket, packetBody);
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

const ByteBuffer createUserIdPacket(const std::string &userName, const std::string &email) {
  ByteBuffer packetBody;
  // FIXME -- encoding or validation needed?
  std::string userNameAndEmail = userName + " <" + email + ">";
  std::vector<uint8_t> userNameAndEmailByteVector(userNameAndEmail.begin(), userNameAndEmail.end());
  packetBody.append(userNameAndEmailByteVector);
  return createPacket(pTagUserIdPacket, packetBody);
};


: ByteArray by lazy {
val out = ByteStreams.newDataOutput()

// Issuer (0x10)
Subpacket(0x10, out).apply {
write(secretPacket.publicPacket.keyId())
write()
}

out.toByteArray()
}

const ByteBuffer createSignaturePacket(const ByteBuffer &secretKey, ByteBuffer &publicKey, ByteBuffer userIdPacket, uint32_t timestamp) {
  ByteBuffer publicPacket = createPublicPacket(publicKey, timestamp);
  ByteBuffer secretPacket = createSecretPacket(secretKey, publicKey, timestamp);

  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.writeByte(0x13); //   signatureType: "Positive certification of a User ID and Public-Key packet. (0x13)"
  packetBody.writeByte(Ed25519Algorithm);
  packetBody.writeByte(Sha256Algorithm);

  const ByteBuffer pubicKeyFingerprint = getPublicKeyFingerprint(publicPacket);
  const ByteBuffer publicKeyId = getPublicKeyId(pubicKeyFingerprint);

  ByteBuffer hashedSubpackets;
  // Issuer Fingerprint)
  {
    ByteBuffer body;
    body.writeByte(Version);
    body.append(pubicKeyFingerprint);
    hashedSubpackets.append(createPacket(0x21 /* issuer */, body));
  } {
  // Signature Creation Time (0x2)
    ByteBuffer body;
    body.write32Bits(timestamp);
    hashedSubpackets.append(createPacket(0x02, body));
  } {
  // Key Flags (0x1b)
    ByteBuffer body;
    body.writeByte(0x01); // Certify (0x1)
    hashedSubpackets.append(createPacket(0x1b, body));
  } {
  // Preferred Symmetric Algorithms (0xb)
    ByteBuffer body;
    body.writeByte(0x09); // AES with 256-bit key (0x9)
    body.writeByte(0x08); // AES with 192-bit key (0x8)
    body.writeByte(0x07); // AES with 128-bit key (0x7)
    body.writeByte(0x01); // TripleDES (DES-EDE, 168 bit key derived from 192) (0x2)
    hashedSubpackets.append(createPacket(0x0b, body));
  } {
  // Preferred Hash Algorithms (0x15)
    ByteBuffer body;
    body.writeByte(0x0a); // SHA512 (0xa)
    body.writeByte(0x09); // SHA384 (0x9)
    body.writeByte(0x08); // SHA256 (0x8)
    body.writeByte(0x0b); // SHA224 (0xb)
    body.writeByte(0x02); // SHA1 (0x2)
    hashedSubpackets.append(createPacket(0x15, body));
  } {
  // Preferred Compression Algorithms (0x16)
    ByteBuffer body;
    body.writeByte(0x02); // ZLIB (0x2)
    body.writeByte(0x03); // BZip2 (0x3)
    body.writeByte(0x01); // ZIP (0x1)
    hashedSubpackets.append(createPacket(0x16, body));
  } {
  // Features (0x1e)
    ByteBuffer body;
    body.writeByte(0x01); // Modification detection (0x1)
    hashedSubpackets.append(createPacket(0x1e, body));
  } {
  // Key Server Preferences (0x17)
    ByteBuffer body;
    body.writeByte(0x80); // No-modify (0x80)
    hashedSubpackets.append(createPacket(0x17, body));
  }

  // Write the subpackets that will be part of the hash, prefixed
  // by the length of all the subpackets combined.
  packetBody.write16Bits(hashedSubpackets.size()); // hashed_area_len
  packetBody.append(hashedSubpackets);

  // Calculate the SHA256-bit hash of the packet before appending the
  // unhashed subpackets (which, as the name implies, shouldn't be hashed).
  ByteBuffer preimage;
  preimage.append(publicPacket, 2); // skip 2 byte packet header of tag byte and length byte
  preimage.append(userIdPacket, 2); // skip 2 byte packet header of tag byte and length byte
  preimage.append(packetBody); // no need to skip since we haven't put the body in a packet yet
  unsigned char sha256HashArray[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(sha256HashArray, preimage.byteVector.data(), preimage.byteVector.size());
  ByteBuffer sha256Hash(crypto_hash_sha256_BYTES, sha256HashArray);

  // The unhashed subpackets should not be hashed/signed.
  // (It's just a keyId which can be re-derived from the hashed content.)
  ByteBuffer unhashedSubpackets;
  {
    // Issuer 0x10 (keyId which is last 8 bytes of SHA256 of public key packet body)
    unhashedSubpackets.append(createPacket(0x10 /* issuer */, publicKeyId));
  }
  packetBody.write16Bits(unhashedSubpackets.size()); // unhashed_area_len
  packetBody.append(unhashedSubpackets);

  // write first two bytes of SHA256 hash of the signature before writing the signature
  // itself
  packetBody.writeByte(sha256Hash.byteVector[0]);
  packetBody.writeByte(sha256Hash.byteVector[1]);

  // Sign the hash
  unsigned char signatureArray[crypto_sign_BYTES];
  crypto_sign_detached(signatureArray, NULL, sha256HashArray, crypto_hash_sha256_BYTES, secretKey.byteVector.data());
  ByteBuffer signature(crypto_sign_BYTES, signatureArray);

  // Append the signature point, which is two 256-bit numbers (r and s),
  // which should thus be wrapped using the wrapping encoding for numbers.
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(signature.slice(0,32)));
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(signature.slice(32,32)));
  return createPacket(pTagSignaturePacket, packetBody);
}

