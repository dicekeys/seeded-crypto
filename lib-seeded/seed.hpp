#pragma once

#include "sodium-buffer.hpp"
#include <string>

/**
 * @brief A seed/secret, which is itself (re)derived from another
 * secret seed and set of key-derivation specified options in
 *  @ref key_derivation_options_format.
 * 
 * Because seed derivation uses a one-way function, this seed can be shared without revealing the
 * secret used to derive it.
 * It can then be used and, if lost, re-derived from the original seed and
 * keyDerviationOptionsJson that were first used to derive it.
 */
class Seed {
public:
  /**
   * @brief The binary representation of the generated seed.
   */
  const SodiumBuffer seedBytes;
    /**
   * @brief A string in  @ref key_derivation_options_format string
   * which specifies how the constructor will derive the
   * seedBytes from the original secret seed.
   */
  const std::string& keyDerivationOptionsJson;

  /**
   * @brief Construct this object as a copy of another object
   * 
   * @param other The Seed to copy into this new object
   */
  Seed(
    const Seed &other
  );

  /**
   * @brief Construct (reconstitute) a Seed from its JSON
   * representation.
   * 
   * @param seedAsJson A Seed serialized in JSON format
   * via a previous call to toJson.
   */
  Seed(
    const std::string& seedAsJson
  );

  /**
   * @brief Derive a seed from an existing secret seed and a set of
   * key-derivation options in @ref key_derivation_options_format.
   * 
   * @param secretSeedBytes The secret seed from which this seed should be
   * derived. Once the seed is derived, you won't need the secretSeedBytes
   * again unless you need to re-derive this seed.
   * @param keyDerivationOptionsJson The key-derivation options in @ref key_derivation_options_format.
   */
  Seed(
    const SodiumBuffer& secretSeedBytes,
    const std::string& keyDerivationOptionsJson = ""
  );

  /**
   * @brief Derive a seed from an existing secret seed string and a set of
   * key-derivation options in @ref key_derivation_options_format.
   * 
   * @param secretSeedString The secret seed string from which this seed should be
   * derived. Once the seed is derived, you won't need the secretSeedBytes
   * again unless you need to re-derive this seed.
   * @param keyDerivationOptionsJson The key-derivation options in @ref key_derivation_options_format.
   */
  Seed(
    const std::string& secretSeedString,
    const std::string& keyDerivationOptionsJson
  );

  /**
   * @brief Serialize this object to a JSON-formatted string
   * 
   * It can be reconstituted by calling the constructor with this string.
   * 
   * @param indent The number of characters to indent the JSON (optional)
   * @param indent_char The character with which to indent the JSON (optional)
   * @return const std::string A Seed serialized to JSON format.
   */
  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;

protected:

  /**
   * @brief An internal help function to re-constitute a Seed from JSON format
   */
  static Seed fromJson(
    const std::string& seedAsJson
  );

};
