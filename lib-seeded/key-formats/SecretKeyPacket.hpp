#pragma once

#include "ByteBuffer.hpp"
#include "../signing-key.hpp"
#include "PublicKeyPacket.hpp"

class SecretKeyPacket : public OpenPgpPacket {
public:
  const ByteBuffer secretKey;
  const uint32_t timestamp;
  const ByteBuffer body;

  SecretKeyPacket(
    const PublicKeyPacket& publicKeyPacket,
    const ByteBuffer& _secretKey,
    uint32_t _timestamp
  );

  const ByteBuffer& getBody() const override;

};