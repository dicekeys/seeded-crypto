#pragma once

#include "ByteBuffer.hpp"
#include "../signing-key.hpp"
#include "PublicKeyPacket.hpp"

//const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey);
//const ByteBuffer createEd25519EdDsaSecretKeyPacket(
//    const ByteBuffer &secretKey,
//    const EdDsaPublicPacket& publicKeyPacket,
//    uint32_t timestamp
//);
//
//const ByteBuffer createEd25519EdDsaSecretKeyPacket(
//  const SigningKey& signingKey,
//  uint32_t timestamp
//);

class SecretKeyPacket: public OpenPgpPacket {
public:
  const ByteBuffer secretKey;
  const uint32_t timestamp;
  const ByteBuffer body;

  SecretKeyPacket(
    const EdDsaPublicPacket& publicKeyPacket,
    const ByteBuffer& _secretKey,
    uint32_t _timestamp
  );

  const ByteBuffer& getBody() const override;

};