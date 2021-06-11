#pragma once

#include "ByteBuffer.hpp"

const ByteBuffer createSignaturePacket(
    const ByteBuffer &secretKey,
    const ByteBuffer &publicKey,
    const ByteBuffer &userIdPacketBody,
    uint32_t timestamp
);


const ByteBuffer createSignaturePacketBodyIncludedInHash(
  const ByteBuffer& pubicKeyFingerprint,
  uint32_t timestamp
);
const ByteBuffer createSignaturePacketHashPreImage(
  const ByteBuffer& publicKeyPacketBody,
  const ByteBuffer& userIdPacketBody,
  const ByteBuffer& signaturePacketBodyIncludedInHash
);
const ByteBuffer createPublicKeyPacketHashPreimage(const ByteBuffer& publicKeyPacketBody);