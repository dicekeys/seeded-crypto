#pragma once

#include "../signing-key.hpp"
#include <random>
#include "ByteBuffer.hpp"

inline uint32_t get32RandomBits () {
    std::random_device rd;     // only used once to initialise (seed) engine
    std::mt19937 rng(rd());    // random-number engine used (Mersenne-Twister in this case)
    std::uniform_int_distribution<uint32_t> uni(0, 0xffffffff); // guaranteed unbiased
    return uni(rng);
}

const std::string getOpenSSHPublicKeyEd25519(const SignatureVerificationKey &publicKey);

const ByteBuffer getOpenSSHPrivateKeyEd25519(
        const SigningKey &signingKey,
        const std::string comment,
        uint32_t checksum = get32RandomBits()
);

const std::string getOpenSshPemPrivateKeyEd25519(
  const SigningKey& signingKey,
  const std::string comment,
  uint32_t checksum = get32RandomBits()
);