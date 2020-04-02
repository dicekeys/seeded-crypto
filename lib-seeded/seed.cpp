#include "./seed.hpp"
#include "generate-seed.hpp"

Seed::Seed(
  const SodiumBuffer& _seed
) : seed(_seed) {}

Seed::Seed(
  const std::string& seedString,
  const std::string& keyDerivationOptionsJson
) : Seed(
  generateSeed(
    seedString,
    keyDerivationOptionsJson,
    KeyDerivationOptionsJson::KeyType::Seed
  )
) {}

const SodiumBuffer Seed::reveal(
) const {
  return seed;
};
