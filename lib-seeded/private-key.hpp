#pragma once

#include "sodium-buffer.hpp"
#include "public-key.hpp"

/**
 * @brief A PrivateKey is used to _unseal_ messages sealed with its
 * corressponding PublicKey.
 * The PrivateKey and PublicKey are generated
 * from a seed and a set of key-derivation specified options in JSON format
 * RefKDO.
 * 
 * The PrivateKey includes a copy of the PublicKey, which can be
 * reconstituted as a PublicKey object via the getPublicKey method.
 */
class PrivateKey {
public:
  /**
   * @brief The libSodium private key used for unsealing
   */
  const SodiumBuffer privateKeyBytes;
  /**
   * @brief The libsodium public key used for sealing
   */
  const std::vector<unsigned char> publicKeyBytes;
  /**
   * @brief A JSON string storing the options used to derive the key from a seed. RefKDO
   */
  const std::string keyDerivationOptionsJson;

  /**
   * @brief Construct a new PrivateKey by passing its members.
   */
  PrivateKey(
    const SodiumBuffer privateKeyBytes,
    const std::vector<unsigned char> publicKeyBytes,
    const std::string keyDerivationOptionsJson
  );

  /**
   * @brief Construct a new PrivateKey by deriving a public/private
   * key pair from a seedBuffer and a set of key-derivation options
   * in JSON format. RefKDO
   * 
   * @param seedBuffer The seed as sequence of bytes
   * @param keyDerivationOptionsJson The key-derivation options in JSON format. RefKDO
   */
  PrivateKey(
    const SodiumBuffer& seedBuffer,
    const std::string& keyDerivationOptionsJson
  );

  /**
   * @brief Construct a new PrivateKey by deriving a public/private
   * key pair from a seed string and a set of key-derivation options
   * in JSON format. RefKDO
   * 
   * @param seedString The private seed which is used to generate the key pair.
   * Anyone who knows (or can guess) this seed can re-generate the key pair
   * by passing it along with the keyDerivationOptionsJson.
   * @param keyDerivationOptionsJson The key-derivation options in JSON format. RefKDO
   */
  PrivateKey(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  /**
   * @brief Construct (reconstitute) from serialized JSON format
   * 
   * @param PrivateKeyAsJson 
   */
  PrivateKey(const std::string &PrivateKeyAsJson);

  /**
   * @brief Construct by copying another PrivateKey
   */
  PrivateKey(
    const PrivateKey& other
  );

  /**
   * @brief Get the PublicKey used to seal messages that can be unsealed 
   * with this PrivateKey
   */
  const PublicKey getPublicKey() const;

  /**
   * @brief Unseal a message 
   * 
   * @param ciphertext The sealed message to be unsealed
   * @param ciphertextLength The length of the sealed message
   * @param postDecryptionInstructionsJson If this optional value was
   * set during the PublicKey::seal operation, the same value must
   * be provided to unseal the message or the operation will fail.
   * @return const SodiumBuffer 
   * 
   * @exception CryptographicVerificationFailure Thrown if the ciphertext
   * is not valid and cannot be unsealed.
   */
  const SodiumBuffer unseal(
    const unsigned char* ciphertext,
    const size_t ciphertextLength,
    const std::string &postDecryptionInstructionsJson
  ) const;

  /**
   * @brief Unseal a message 
   * 
   * @param ciphertext The sealed message to be unsealed
   * @param postDecryptionInstructionsJson If this optional value was
   * set during the PublicKey::seal operation, the same value must
   * be provided to unseal the message or the operation will fail.
   * @return const SodiumBuffer 
   * 
   * @exception CryptographicVerificationFailure Thrown if the ciphertext
   * is not valid and cannot be unsealed.
   */
  const SodiumBuffer unseal(
    const std::vector<unsigned char> &ciphertext,
    const std::string& postDecryptionInstructionsJson = ""
  ) const;

  /**
   * @brief Serialize this object to a JSON-formatted string
   * 
   * It can be reconstituted by calling the constructor with this string.
   * 
   * @param indent The number of characters to indent the JSON (optional)
   * @param indent_char The character with which to indent the JSON (optional)
   * @return const std::string A PrivateKey serialized to JSON format.
   */
  const std::string toJson(
    int indent = -1,
    const char indent_char = ' '
  ) const;

};
