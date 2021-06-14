#pragma once

#include "ByteBuffer.hpp"
#include "EdDsaPublicPacket.hpp"
#include "UserPacket.hpp"

const ByteBuffer createSignaturePacket(
    const ByteBuffer &secretKey,
    const EdDsaPublicPacket& publicKeyPacket,
    const UserPacket& userPacket,
    uint32_t timestamp
);


const ByteBuffer createSignaturePacketBodyIncludedInHash(
  const ByteBuffer& pubicKeyFingerprint,
  uint32_t timestamp
);
const ByteBuffer createSignaturePacketHashPreImage(
  const ByteBuffer& EdDsaPublicPacketBody,
  const UserPacket& userPacket,
  const ByteBuffer& signaturePacketBodyIncludedInHash
);
const ByteBuffer createEdDsaPublicPacketHashPreimage(const ByteBuffer& EdDsaPublicPacketBody);