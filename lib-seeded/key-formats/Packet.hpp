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
const ByteBuffer publicKeyFingerprint(const ByteBuffer &publicKeyPacket) {
  ByteBuffer preimage;
  preimage.writeByte(0x99);
  preimage.write16Bits(publicKeyPacket.size());
  preimage.append(publicKeyPacket);
  sha1 hash = sha1();
  hash.add(preimage.byteVector.data(), preimage.byteVector.size());
  hash.finalize();
  return ByteBuffer(SHA1_HASH_LENGTH_IN_BYTES, (uint8_t*) hash.state);
}

const ByteBuffer createUserIdPacket(const std::string &userName, const std::string &email) {
  ByteBuffer packetBody;
  // FIXME -- encoding or validation needed?
  std::string userNameAndEmail = userName + " <" + email + ">";
  std::vector<uint8_t> userNameAndEmailByteVector(userNameAndEmail.begin(), userNameAndEmail.end());
  packetBody.append(userNameAndEmailByteVector);
  return createPacket(pTagUserIdPacket, packetBody);
};

const ByteBuffer createSignaturePacket(const ByteBuffer &secretKey, ByteBuffer &publicKey, ByteBuffer userIdPacket, uint32_t timestamp) {
  ByteBuffer publicPacket = createPublicPacket(publicKey, timestamp);
  ByteBuffer secretPacket = createSecretPacket(secretKey, publicKey, timestamp);

  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.writeByte(0x13); //   signatureType: "Positive certification of a User ID and Public-Key packet. (0x13)"
  packetBody.writeByte(Ed25519Algorithm);
  packetBody.writeByte(Sha256Algorithm);

  packetBody.write16Bits(hashedSubPackets.size); // hashed_area_len
  packetBody.append(hashedSubPackets);

  packetBody.write16Bits(unhashedSubPackets.size); // unhashed_area_len
  packetBody.append(unhashedSubPackets);


  ByteBuffer preimage;
  preimage.append(publicPacket, 2); // skip 2 byte packet header of tag byte and length byte
  preimage.append(userIdPacket, 2); // skip 2 byte packet header of tag byte and length byte
  preimage.append(packetBody); // no need to skip since we haven't put the body in a packet yet
  unsigned char sha256HashArray[crypto_hash_sha256_BYTES];
  crypto_hash_sha256(sha256HashArray, preimage.byteVector.data(), preimage.byteVector.size());
  ByteBuffer sha256Hash(crypto_hash_sha256_BYTES, sha256HashArray);

  // write first two bytes of SHA256 hash
  packetBody.writeByte(sha256Hash.byteVector[0]);
  packetBody.writeByte(sha256Hash.byteVector[1]);

  // val signature = ByteArray(Ed25519PrivateKeyParameters.SIGNATURE_SIZE)
  // privateKeyEd255119.sign(Ed25519.Algorithm.Ed25519, null, hash, 0, hash.size, signature, 0)
  // const auto signature = ByteArray(Ed25519PrivateKeyParameters.SIGNATURE_SIZE)
  // privateKeyEd255119.sign(Ed25519.Algorithm.Ed25519, null, hash, 0, hash.size, signature, 0)
  unsigned char signatureArray[crypto_sign_BYTES];
  crypto_sign_detached(signatureArray, NULL, sha256HashArray, crypto_hash_sha256_BYTES, secretKey.byteVector.data());
  ByteBuffer signature(crypto_sign_BYTES, signatureArray);

  // split signature into 2 parts of 32 bytes
  // r & s
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(signature.slice(0,32)));
  packetBody.append(wrapKeyWithLengthPrefixAndTrim(signature.slice(32,32)));
  return createPacket(pTagSignaturePacket, packetBody);
}

// class Packet {
//   public:
//     // RFC4880 - Section 4
//     // Explanation: https://under-the-hood.sequoia-pgp.org/packet-structure/
//     virtual uint8_t pTag(); // Also known as CTB (Cipher Type Byte)
//     virtual BodyBuffer body();

//     // virtual std::vector<uint8_t> hash(digest: MessageDigest);
    
//     const ByteBuffer toByteArray() {
//       creatPacket(pTag(), body()).byteVector;
//     }

//     static const uint8_t Version = 0x04;
//     static const uint8_t Sha256Algorithm = 0x08; // RFC4880-bis-10 - Section 9.5 - 08 - SHA2-256 [FIPS180]
//     static const uint8_t Ed25519Algorithm = 0x16; // RFC4880-bis-10 - Section 9.1 - 22 (0x16) - EdDSA [RFC8032]
//     static const std::vector<uint8_t> Ed25519CurveOid() { return std::vector<uint8_t>({0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}); }; // RFC4880-bis-10 - Section 9.2.  ECC Curve OID
// };

