#pragma once
#include "Packet.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "sodium.h"

const ByteBuffer createSignaturePacket(
    const ByteBuffer &secretKey,
    const ByteBuffer &publicKey,
    const ByteBuffer userIdPacket,
    uint32_t timestamp
) {
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

