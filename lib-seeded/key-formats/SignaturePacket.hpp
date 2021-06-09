#pragma once

#include "ByteBuffer.hpp"

const ByteBuffer createSignaturePacket(
    const ByteBuffer &secretKey,
    const ByteBuffer &publicKey,
    const ByteBuffer userIdPacket,
    uint32_t timestamp
);
