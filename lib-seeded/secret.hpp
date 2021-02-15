#pragma once

#include "sodium-buffer.hpp"
#include <string>

/**
 * @brief A secret derived from a seed string 
 * and set of options in
 * @ref recipe_format.
 * 
 * Because the secret is derived using a one-way function,
 * its value does not reveal the secret seed used to derive it.
 * Rather, clients can use this secret knowing that, if lost,
 * it can be re-derived from the same seed and
 * recipe that were first used to derive it.
 * 
 * @ingroup DerivedFromSeeds
 */
class Secret {
public:
  /**
   * @brief The binary representation of the derived secret.
   */
  const SodiumBuffer secretBytes;
    /**
   * @brief A string in @ref recipe_format string
   * which specifies how the constructor will derive the
   * secretBytes from the original secret seed.
   */
  const std::string recipe;

  /**
   * @brief Construct this object as a copy of another object
   * 
   * @param other The Secret to copy into this new object
   */
  Secret(
    const Secret &other
  );

  /**
   * Construct a secret from its two fields: the secretBytes
   * and the recipe.
   * 
   * @param secretBytes The derived secret.
   * @param recipe The recipe in @ref recipe_format.
   */
  Secret(
    const SodiumBuffer& secretBytes,
    const std::string& recipe = {}
  );

  /**
   * @brief Derive a secret from a seed secret and a set of
   * recipe in @ref recipe_format.
   * 
   * @param seedString The secret seed string from which this secret should be
   * derived. Once the secret is derived, you won't need the secretSeedBytes
   * again unless you need to re-derive this secret.
   * @param recipe The recipe in @ref recipe_format.
   */
  Secret(
    const std::string& seedString,
    const std::string& recipe
  );

  /**
   * @brief Derive a secret from a seed secret and a set of
   * recipe in @ref recipe_format.
   * 
   * @param seedString The secret seed string from which this secret should be
   * derived. Once the secret is derived, you won't need the secretSeedBytes
   * again unless you need to re-derive this secret.
   * @param recipe The recipe in @ref recipe_format.
   */
  static Secret deriveFromSeed(
    const std::string& seedString,
    const std::string& recipe
  );


  /**
   * @brief Serialize this object to a JSON-formatted string
   * 
   * It can be reconstituted by calling the constructor with this string.
   * 
   * @param indent The number of characters to indent the JSON (optional)
   * @param indent_char The character with which to indent the JSON (optional)
   * @return const std::string A Secret serialized to JSON format.
   */
  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;

  /**
   * @brief Serialize to byte array as a list of:
   *   (secretBytes, recipe)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  const SodiumBuffer toSerializedBinaryForm() const;

  /**
   * @brief Deserialize from a byte array stored as a list of:
   *   (secretBytes, recipe)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  static Secret fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm);

  /**
   * @brief Construct (reconstitute) a Secret from its JSON
   * representation.
   * 
   * @param seedAsJson A Secret serialized in JSON format
   * via a previous call to toJson.
   */
  static Secret fromJson(
    const std::string& seedAsJson
  );

};
