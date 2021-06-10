#pragma once

#include "ByteBuffer.hpp"

const ByteBuffer taggedPublicKey(const ByteBuffer &publicKey);
const ByteBuffer createPublicKeyPacketBody(const ByteBuffer& publicKeyBytes, uint32_t timestamp);
const ByteBuffer createPublicKeyPacket(const ByteBuffer& publicKeyPacketBody);
const ByteBuffer createPublicKeyPacketHashPreimage(const ByteBuffer& publicKeyPacketBody);
const ByteBuffer createPublicKeyPacket(const ByteBuffer &publicKey, uint32_t timestamp);
const ByteBuffer getPublicKeyFingerprint(const ByteBuffer & publicKeyPacketBody);
const ByteBuffer getPublicKeyIdFromFingerprint(const ByteBuffer& publicKeyFingerprint);
const ByteBuffer getPublicKeyIdFromPublicKeyPacketBody(const ByteBuffer& publicKeyPacketBody);
