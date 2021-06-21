#pragma once

#include "ByteBuffer.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "UserPacket.hpp"

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
    uint8_t version,
    const SigningKey& signingKey,
    const UserPacket& userPacket,
    const SecretKeyPacket& secretPacket,
    const EdDsaPublicPacket& publicKeyPacket,
    uint32_t _timestamp
  );

  const ByteBuffer& getBody() const override;

};