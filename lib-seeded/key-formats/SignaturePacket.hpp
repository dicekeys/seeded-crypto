#pragma once

#include "ByteBuffer.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "UserPacket.hpp"

/**
 * @brief A class representing an OpenPGP Signature Packet
 * 
 * 5.2.  Signature Packet (Tag 2)
 *
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 *
 * Implementations MUST generate version 5 signatures when using a
 * version 5 key.  Implementations SHOULD generate V4 signatures with
 * version 4 keys.  Implementations MUST NOT create version 3
 * signatures; they MAY accept version 3 signatures.
 * 
 */
class SignaturePacket : public OpenPgpPacket {
public:
  const uint32_t timestamp;
  const ByteBuffer packetBodyIncludedInSignatureHash;
  const ByteBuffer signatureHashPreImage;
  const ByteBuffer signatureHashSha256;
  const ByteBuffer signature;
  const ByteBuffer unhashedSubpacketsWithSizePrefix;
  const ByteBuffer body;

  SignaturePacket(
    const SigningKey& signingKey,
    const UserPacket& userPacket,
    const EdDsaPublicPacket& publicKeyPacket,
    uint32_t _timestamp
  );

  const ByteBuffer& getBody() const override;

};