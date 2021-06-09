#pragma once

#include "ByteBuffer.hpp"

const ByteBuffer taggedPublicKey(const ByteBuffer &publicKey);
const ByteBuffer createPublicPacket(const ByteBuffer &publicKey, uint32_t timestamp);

// A V4 fingerprint is the 160-bit SHA-1 hash of the octet 0x99,
// followed by the two-octet packet length, followed by the entire
// Public-Key packet starting with the version field.
const ByteBuffer getPublicKeyFingerprint(const ByteBuffer &publicKeyPacket);

// The Key ID is the low-order 64 bits of the fingerprint.
const ByteBuffer getPublicKeyId(const ByteBuffer &publicKeyFingerprint);
