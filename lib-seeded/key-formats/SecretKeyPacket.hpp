#pragma once

#include "ByteBuffer.hpp"
#include "../signing-key.hpp"

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey);
const ByteBuffer createEd25519SecretKeyPacket(
      const ByteBuffer &secretKey,
      const ByteBuffer &publicKey,
      uint32_t timestamp
);

const ByteBuffer createEd25519SecretKeyPacket(
  const SigningKey& signingKey,
  uint32_t timestamp
);