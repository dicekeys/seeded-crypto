#pragma once

#include "ByteBuffer.hpp"

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey);
const ByteBuffer createSecretPacket(
      const ByteBuffer &secretKey,
      const ByteBuffer &publicKey,
      uint32_t timestamp
);