#pragma once

#include "sodium-buffer.hpp"
#include "key-derivation-options.hpp"
#include "exceptions.hpp"

// We call this function to generate and write the key into memory so that the
// class instance can treat the key as a constant.
const SodiumBuffer generateSeed(
  const std::string& seedString,
  const std::string& keyDerivationOptionsJson,
  const KeyDerivationOptionsJson::KeyType keyTypeRequired,
  const size_t keyLengthInBytesRequired = 0
);