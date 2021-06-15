#include <sodium.h>
#include "../sodium-buffer.hpp"
#include "OpenPgpPacket.hpp"
#include "SignaturePacket.hpp"
#include "EdDsaPublicPacket.hpp"
#include "EdDsaSecretKeyPacket.hpp"
#include "UserPacket.hpp"

const ByteBuffer createSubpacket(uint8_t type, const ByteBuffer& subpacketBodyBuffer) {
  ByteBuffer packet;
  // RFC2440 Section 4.2.2
  // Should follow the spec as described in RFC4880-bis-10 - Section 5.2.3.1.
  // Hardcoded to one byte as 191 length is enough for our use case.
  packet.writeByte(subpacketBodyBuffer.size() + 1); // + 1 is the type byte
  packet.writeByte(type);
  packet.append(subpacketBodyBuffer);
  return packet;
}

const ByteBuffer createSignedSubpackets(const ByteBuffer & pubicKeyFingerprint, uint32_t timestamp) {
  ByteBuffer signedSubpackets;
  // Issuer Fingerprint
  {
    ByteBuffer body;
    body.writeByte(VERSION_4);
    body.append(pubicKeyFingerprint);
    signedSubpackets.append(createSubpacket(0x21 /* issuer */, body));
  } {
    // Signature Creation Time (0x2)
    ByteBuffer body;
    body.write32Bits(timestamp);
    signedSubpackets.append(createSubpacket(0x02, body));
  } {
    // Key Flags (0x1b)
    ByteBuffer body;
    body.writeByte(0x01); // Certify (0x1)
    signedSubpackets.append(createSubpacket(0x1b, body));
  } {
    // Preferred Symmetric Algorithms (0xb)
    ByteBuffer body;
    body.writeByte(0x09); // AES with 256-bit key (0x9)
    body.writeByte(0x08); // AES with 192-bit key (0x8)
    body.writeByte(0x07); // AES with 128-bit key (0x7)
    body.writeByte(0x02); // TripleDES (DES-EDE, 168 bit key derived from 192) (0x2)
    signedSubpackets.append(createSubpacket(0x0b, body));
  } {
    // Preferred Hash Algorithms (0x15)
    ByteBuffer body;
    body.writeByte(0x0a); // SHA512 (0xa)
    body.writeByte(0x09); // SHA384 (0x9)
    body.writeByte(0x08); // SHA256 (0x8)
    body.writeByte(0x0b); // SHA224 (0xb)
    body.writeByte(0x02); // SHA1 (0x2)
    signedSubpackets.append(createSubpacket(0x15, body));
  } {
    // Preferred Compression Algorithms (0x16)
    ByteBuffer body;
    body.writeByte(0x02); // ZLIB (0x2)
    body.writeByte(0x03); // BZip2 (0x3)
    body.writeByte(0x01); // ZIP (0x1)
    signedSubpackets.append(createSubpacket(0x16, body));
  } {
    // Features (0x1e)
    ByteBuffer body;
    body.writeByte(0x01); // Modification detection (0x1)
    signedSubpackets.append(createSubpacket(0x1e, body));
  } {
    // Key Server Preferences (0x17)
    ByteBuffer body;
    body.writeByte(0x80); // No-modify (0x80)
    signedSubpackets.append(createSubpacket(0x17, body));
  }
  return signedSubpackets;
}

const ByteBuffer createSignaturePacketBodyIncludedInHash(
  const ByteBuffer& pubicKeyFingerprint,
  uint32_t timestamp
) {
    ByteBuffer packetBody;
    packetBody.writeByte(VERSION_4);
    packetBody.writeByte(0x13); //   signatureType: "Positive certification of a User ID and Public-Key packet. (0x13)"
    packetBody.writeByte(ALGORITHM_ED_DSA);
    packetBody.writeByte(ALGORITHM_HASH_SHA_256);

    // Write the subpackets that will be part of the hash, prefixed
    // by the length of all the subpackets combined.
    ByteBuffer hashedSubpackets = createSignedSubpackets(pubicKeyFingerprint, timestamp);
    packetBody.write16Bits(hashedSubpackets.size()); // hashed_area_len
    packetBody.append(hashedSubpackets);
    return packetBody;
}


const ByteBuffer createSignaturePacketHashPreImage(
  const EdDsaPublicPacket& publicKeyPacket,
  const UserPacket& userPacket,
  const ByteBuffer& signaturePacketBodyIncludedInHash
) {
  ByteBuffer preImage;
  preImage.append(publicKeyPacket.preImage);
  preImage.append(userPacket.getPreImage());
  preImage.append(signaturePacketBodyIncludedInHash);
  // Document?
  preImage.writeByte(VERSION_4);
  preImage.writeByte(0xff);
  // The signature hash size is the size of the packetBody constructed so far,
  // which is the content to be used as a hash preimage.
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
  // write first two bytes of SHA256 hash of the signature before writing the signature
  // itself
  signatureBody.writeByte(signatureHashSha256.byteVector[0]);
  signatureBody.writeByte(signatureHashSha256.byteVector[1]);

  ByteBuffer signature(crypto_sign_BYTES);
  //    const auto sk = SigningKey(SodiumBuffer(secretKey.byteVector), "");
  crypto_sign_detached(signature.byteVector.data(), NULL, signatureHashSha256.byteVector.data(), crypto_hash_sha256_BYTES, sk.signingKeyBytes.data);

  //// Append the signature point, which is two 256-bit numbers (r and s),
  //// which should thus be wrapped using the wrapping encoding for numbers.
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
  const SigningKey& signingKey,
  const UserPacket& userPacket,
  const EdDsaSecretKeyPacket& secretPacket,
  const EdDsaPublicPacket& publicKeyPacket,
  uint32_t _timestamp
) :
  OpenPgpPacket(PTAG_SIGNATURE),
  timestamp(_timestamp),
  packetBodyIncludedInSignatureHash(createSignaturePacketBodyIncludedInHash(publicKeyPacket.fingerprint, _timestamp)),
  signatureHashPreImage(createSignaturePacketHashPreImage(publicKeyPacket, userPacket, packetBodyIncludedInSignatureHash)),
  signatureHashSha256(createSignatureHashSHA256(signatureHashPreImage)),
  signature(createSignature(signingKey, signatureHashSha256)),
  unhashedSubpacketsWithSizePrefix(createUnhashedSubpacketsWithSizePrefix(publicKeyPacket.keyId)),
  body(createSignaturePacketBody(packetBodyIncludedInSignatureHash, signature, unhashedSubpacketsWithSizePrefix))
{}

const ByteBuffer& SignaturePacket::getBody() const { return body; };
