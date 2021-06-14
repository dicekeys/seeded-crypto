#pragma once

#include "ByteBuffer.hpp"
#include "../signing-key.hpp"
#include "EdDsaPublicPacket.hpp"

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey);
const ByteBuffer createEd25519SecretKeyPacket(
    const ByteBuffer &secretKey,
    const EdDsaPublicPacket& publicKeyPacket,
    uint32_t timestamp
);

const ByteBuffer createEd25519SecretKeyPacket(
  const SigningKey& signingKey,
  uint32_t timestamp
);