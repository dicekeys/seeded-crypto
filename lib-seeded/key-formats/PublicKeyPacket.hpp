#pragma once

#include "ByteBuffer.hpp"
#include "OpenPgpPacket.hpp"
#include "KeyConfiguration.hpp"

// const size_t VERSION_4_FINGERPRINT_LENGTH_IN_BYTES_DUE_TO_USE_OF_SHA1 = 20; // 160 bits
// const size_t VERSION_5_FINGERPRINT_LENGTH_IN_BYTES = 32; // 160 bits

class PublicKeyPacket : public OpenPgpPacket {
public:
  const KeyConfiguration keyConfiguration;
  const uint32_t timestamp;
  const ByteBuffer publicKeyBytes;
  const ByteBuffer publicKeyInEdDsaPointFormat;
  const ByteBuffer body;
  const ByteBuffer preImage;
  ByteBuffer fingerprint;
  ByteBuffer keyId;

  const ByteBuffer& getBody() const override;
  PublicKeyPacket(
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp,
    const KeyConfiguration &configuration
  );
};

class EdDsaPublicPacket : public PublicKeyPacket {
public:
  EdDsaPublicPacket(
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp,
    const EdDsaKeyConfiguration &configuration = EdDsaKeyConfiguration()
  );
};

class EcDhPublicPacket : public PublicKeyPacket {
public:
  EcDhPublicPacket(
    const ByteBuffer& _publicKeyBytes,
    uint32_t _timestamp,
    const EcDhKeyConfiguration &configuration = EcDhKeyConfiguration()
  );
};