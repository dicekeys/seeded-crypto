#pragma once

#include "ByteBuffer.hpp"
#include "OpenPgpPacket.hpp"

class EdDsaPublicPacket : public OpenPgpPacket {
public:
  const uint32_t timestamp;
  const ByteBuffer publicKeyBytes;
  const ByteBuffer publicKeyInEdDsaPointFormat;
  const ByteBuffer body;
  const ByteBuffer preimage;
  ByteBuffer fingerprint;
  ByteBuffer keyId;

  const ByteBuffer& getBody() override;
  EdDsaPublicPacket(
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp
  );
};
