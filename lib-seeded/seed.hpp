#pragma once

#include "sodium-buffer.hpp"
#include <string>

class Seed {
private:
  SodiumBuffer seed;

public:

  Seed(
    const SodiumBuffer& seed
  );

  Seed(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  const SodiumBuffer reveal(
  ) const;

};
