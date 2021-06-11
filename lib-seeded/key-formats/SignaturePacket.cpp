#include <sodium.h>
#include "../sodium-buffer.hpp"
#include "Packet.hpp"
#include "SignaturePacket.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
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
  // Issuer Fingerprint)
  {
    ByteBuffer body;
    body.writeByte(Version);
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
    packetBody.writeByte(Version);
    packetBody.writeByte(0x13); //   signatureType: "Positive certification of a User ID and Public-Key packet. (0x13)"
    packetBody.writeByte(Ed25519Algorithm);
    packetBody.writeByte(Sha256Algorithm);

    // Write the subpackets that will be part of the hash, prefixed
    // by the length of all the subpackets combined.
    ByteBuffer hashedSubpackets = createSignedSubpackets(pubicKeyFingerprint, timestamp);
    packetBody.write16Bits(hashedSubpackets.size()); // hashed_area_len
    packetBody.append(hashedSubpackets);
    return packetBody;
}


const ByteBuffer createSignaturePacketHashPreImage(
  const ByteBuffer& publicKeyPacketBody,
  const ByteBuffer& userIdPacketBody,
  const ByteBuffer& signaturePacketBodyIncludedInHash
) {
  ByteBuffer preimage;
  preimage.append(createPublicKeyPacketHashPreimage(publicKeyPacketBody));
  preimage.append(createUserPacketHashPreimage(userIdPacketBody));
  preimage.append(signaturePacketBodyIncludedInHash);
  // Document?
  preimage.writeByte(Version);
  preimage.writeByte(0xff);
  // The signature hash size is the size of the packetBody constructed so far,
  // which is the content to be used as a hash preimage.
  preimage.write32Bits(signaturePacketBodyIncludedInHash.size());
  return preimage;
}

const ByteBuffer createSignaturePacket(
    const ByteBuffer &secretKey,
    const ByteBuffer &publicKey,
    const ByteBuffer &userIdPacketBody,
    uint32_t timestamp
) {
    const ByteBuffer publicKeyPacketBody = createPublicKeyPacketBody(publicKey, timestamp);
    const ByteBuffer pubicKeyFingerprint = getPublicKeyFingerprint(publicKeyPacketBody);
    const ByteBuffer publicKeyId = getPublicKeyIdFromPublicKeyPacketBody(publicKeyPacketBody);

    ByteBuffer packetBody = createSignaturePacketBodyIncludedInHash(pubicKeyFingerprint, timestamp);

    // Calculate the SHA256-bit hash of the packet before appending the
    // unhashed subpackets (which, as the name implies, shouldn't be hashed).
    ByteBuffer signaturePacketBodyIncludedInHash =
      createSignaturePacketBodyIncludedInHash(pubicKeyFingerprint, timestamp);
    ByteBuffer preimage = createSignaturePacketHashPreImage(
      publicKeyPacketBody,
      userIdPacketBody,
      signaturePacketBodyIncludedInHash
    );

    // Calculate the SHA256 hash of the preimage.
    ByteBuffer sha256Hash(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(sha256Hash.byteVector.data(), preimage.byteVector.data(), preimage.byteVector.size());
    
    // The unhashed subpackets should not be hashed/signed.
    // (It's just a keyId which can be re-derived from the hashed content.)
    ByteBuffer unhashedSubpackets;
    {
        // Issuer 0x10 (keyId which is last 8 bytes of SHA256 of public key packet body)
        unhashedSubpackets.append(createSubpacket(0x10 /* issuer */, publicKeyId));
    }
    packetBody.write16Bits(unhashedSubpackets.size()); // unhashed_area_len
    packetBody.append(unhashedSubpackets);
    // write first two bytes of SHA256 hash of the signature before writing the signature
    // itself

    packetBody.writeByte(sha256Hash.byteVector[0]);
    packetBody.writeByte(sha256Hash.byteVector[1]);

    //// Sign the hash
    ByteBuffer signature(crypto_sign_BYTES);
    const auto sk = SigningKey(SodiumBuffer(secretKey.byteVector), "");
    crypto_sign_detached(signature.byteVector.data(), NULL, sha256Hash.byteVector.data(), crypto_hash_sha256_BYTES, sk.signingKeyBytes.data);

    //// Append the signature point, which is two 256-bit numbers (r and s),
    //// which should thus be wrapped using the wrapping encoding for numbers.
    packetBody.append(wrapKeyWithLengthPrefixAndTrim(signature.slice(0,32)));
    packetBody.append(wrapKeyWithLengthPrefixAndTrim(signature.slice(32,32)));
    return createPacket(pTagSignaturePacket, packetBody);
}

