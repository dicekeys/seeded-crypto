#pragma once

#include <string>
#include <vector>
#include "sodium-buffer.hpp"

/**
 * @brief When a message is sealed, the ciphertext is packaged with the derivationOptionsJson
 * in @ref derivation_options_format, as well as any optional unsealing instructions
 * it was sealed with (unsealingInstructions).
 * 
 * @ingroup BuildingBlocks
 */
class PackagedSealedMessage {

public:
    /**
     * @brief The sealed message as a raw array of bytes
     */
    const std::vector<unsigned char> ciphertext;
    /**
     * @brief The derivation options used to generate the
     * encryption/decryption keys.
     */
    const std::string derivationOptionsJson;
    /**
     * @brief Optional public instructions that the sealer
     * requests the unsealer to follow as a condition of unsealing.
     */
    const std::string unsealingInstructions;

    /**
     * @brief Construct directly from the constituent members
     * 
     * @param ciphertext  The binary sealed message
     * @param derivationOptionsJson  The derivation options used to generate the
     * encryption/decryption keys.
     * @param unsealingInstructions Optional public instructions that the sealer
     * requests the unsealer to follow as a condition of unsealing.
     */
    PackagedSealedMessage(
        const std::vector<unsigned char>& ciphertext,
        const std::string& derivationOptionsJson,
        const std::string& unsealingInstructions
    );

    /**
     * The copy constructor
     * @param other An object of the same time to copy.
     */
    PackagedSealedMessage(const PackagedSealedMessage &other);


  /**
   * @brief Serialize to byte array as a list of:
   *   (keyBytes, derivationOptionsJson)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  const SodiumBuffer toSerializedBinaryForm() const;

  /**
   * @brief Deserialize from a byte array stored as a list of:
   *   (keyBytes, derivationOptionsJson)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  static PackagedSealedMessage fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm);

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
  static PackagedSealedMessage fromJson(const std::string& packagedSealedMessageAsJson);

};