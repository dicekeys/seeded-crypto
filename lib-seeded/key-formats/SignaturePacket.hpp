#pragma once

#include "ByteBuffer.hpp"
#include "EdDsaPublicPacket.hpp"

const ByteBuffer createSignaturePacket(
    const ByteBuffer &secretKey,
    const EdDsaPublicPacket& publicKeyPacket,
    const ByteBuffer &userIdPacketBody,
    uint32_t timestamp
);


const ByteBuffer createSignaturePacketBodyIncludedInHash(
  const ByteBuffer& pubicKeyFingerprint,
  uint32_t timestamp
);
const ByteBuffer createSignaturePacketHashPreImage(
  const ByteBuffer& EdDsaPublicPacketBody,
  const ByteBuffer& userIdPacketBody,
  const ByteBuffer& signaturePacketBodyIncludedInHash
);
const ByteBuffer createEdDsaPublicPacketHashPreimage(const ByteBuffer& EdDsaPublicPacketBody);