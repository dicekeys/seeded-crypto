#pragma once

#include <string>
#include <vector>
#include "sodium-buffer.hpp"

class PackagedSealedMessage {

public:
    const std::vector<unsigned char> ciphertext;
    const std::string keyDerivationOptionsJson;
    const std::string postDecryptionInstructionJson;

    /**
     * @brief Construct directly from the constituent members
     * 
     * @param ciphertext 
     * @param keyDerivationOptionsJson 
     * @param postDecryptionInstructionJson 
     */
    PackagedSealedMessage(
        const std::vector<unsigned char> ciphertext,
        const std::string keyDerivationOptionsJson,
        const std::string postDecryptionInstructionJson
    );

    /**
   * @brief Serialize to byte array as a list of:
   *   (keyBytes, keyDerivationOptionsJson)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  const SodiumBuffer toSerializedBinaryForm() const;

  /**
   * @brief Deserialize from a byte array stored as a list of:
   *   (keyBytes, keyDerivationOptionsJson)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  static PackagedSealedMessage fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm);

  /**
   * @brief Serialize this object to a JSON-formatted string
   * 
   * It can be reconstituted by calling the constructor with this string.
   * 
   * @param indent The number of characters to indent the JSON (optional)
   * @param indent_char The character with which to indent the JSON (optional)
   * @return const std::string
   */
  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;
  
  /**
   * @brief Construct by reconstituting this object from a JSON string
   * 
   * @param packagedSealedMessageAsJson The JSON encoding of this object generated
   * by a call to toJson
   */
  static PackagedSealedMessage fromJson(const std::string &packagedSealedMessageAsJson);

};