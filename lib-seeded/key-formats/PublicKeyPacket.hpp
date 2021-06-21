#pragma once

#include "ByteBuffer.hpp"
#include "OpenPgpPacket.hpp"

class PublicKeyConfiguration {
public:
  PublicKeyConfiguration(
    const uint8_t _algorithm,
    const std::vector<uint8_t> _curve
  ) : algorithm(_algorithm), curve(_curve) {}

  const uint8_t algorithm;
  const std::vector<uint8_t> curve;
};

class PublicKeyPacket : public OpenPgpPacket {
public:
  const uint32_t timestamp;
  const ByteBuffer publicKeyBytes;
  const ByteBuffer publicKeyInEdDsaPointFormat;
  const ByteBuffer body;
  const ByteBuffer preImage;
  ByteBuffer fingerprint;
  ByteBuffer keyId;

  const ByteBuffer& getBody() const override;
  PublicKeyPacket(
    const uint8_t version,
    const PublicKeyConfiguration &configuration,
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp
  );
};

class EdDsaPublicPacket : public PublicKeyPacket {
public:
  EdDsaPublicPacket(
    const uint8_t version,
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp
  );
};

class EcDhPublicPacket : public PublicKeyPacket {
public:
  EcDhPublicPacket(
    const uint8_t version,
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp
  );
};