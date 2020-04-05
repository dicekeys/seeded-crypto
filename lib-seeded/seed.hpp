#pragma once

#include "sodium-buffer.hpp"
#include <string>

class Seed {
public:
  const SodiumBuffer seedBytes;
  const std::string& keyDerivationOptionsJson;

  Seed(
    const Seed &other
  );

  Seed(
    const std::string& seedAsJson
  );

  Seed(
    const SodiumBuffer& _seedBytes,
    const std::string& keyDerivationOptionsJson = ""
  );

  Seed(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;

protected:

  // Used by the JSON constructor
  static Seed fromJson(
    const std::string& seedAsJson
  );

};
