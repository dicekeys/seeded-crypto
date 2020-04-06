#pragma once

#include <vector>
#include <string>
#include <sodium.h>
#include "sodium-buffer.hpp"

/**
 * @brief A public key is used in combination with a private (secret) key.
 * The public key is used to _seal_ a message or other data (a _plaintext_)
 * to create a _ciphertext_.  The corresponding private key is required to
 * _unseal_ the ciphertext to recover the original plaintext.
 * The key pair of this public key and the matching private key are generated
 * from a seed and a set of key-derivation specified options in JSON format
 * RefKDO.
 *
 * Sealing provides both encryption, which ensures the contents of the
 * message are confidential, and authentication, which ensures
 * that the message has not been modified since being sealed.
 * We use the verbs seal and unseal, rather than encrypt and decrypt,
 * because the encrypting alone does not confer that the message includes
 * an authentication (integrity) code to prove that it has not been tampered with.
 * 
 * Note that sealing data does not prevent attackers who capture a sealed message
 * (ciphertext) in transit with another validly-sealed message. A SigningKey
 * can be used to sign messages that another party can verify that the
 * message has not been forged or modified since the signer approved it.
 * 
 */
class PublicKey {
protected:
  static PublicKey fromJson(const std::string &publicKeyAsJson);
  
public:
  /**
   * @brief The libsodium public key used for encryption
   */
  const std::vector<unsigned char> publicKeyBytes;
  /**
   * @brief A JSON string storing the options used to derive the public key from a seed
   * 
   * RefKDO
   */
  const std::string keyDerivationOptionsJson;

  /**
   * @brief Construct a new Public Key object by passing its two members.
   * 
   * @param publicKeyBytes 
   * @param keyDerivationOptionsJson 
   */
  PublicKey(
    const std::vector<unsigned char> &publicKeyBytes,
    const std::string &keyDerivationOptionsJson
  );

  /**
   * @brief Construct (reconstitute) from serialized JSON format
   * 
   * @param publicKeyAsJson A public key serialized in JSON format via a previous call to toJson()
   */
  PublicKey(const std::string &publicKeyAsJson);

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
   * @brief *Avoid Using* Seal a message using a raw libsodium public key.
   * 
   * Instead of using this static method, we recommend you use the seal
   * method on an instance of a PublicKey object.
   * This static method is used internally to libsodium's seal operation.
   * We have exposed so that others can replicate the internals of this class
   * if necessary, but recommend that only when there are reasons not to call
   * the non-static seal operation on an instance of this class.
   * 
   * @param message The plaintext message to seal
   * @param publicKey The public key matching the private key used to unseal it.
   * @param postDecryptionInstructionsJson If this optional string is
   * passed, the same string must be passed to unseal the message.
   * RefPDI.
   * @return const std::vector<unsigned char> The sealed message (ciphertext)
   */
  static const std::vector<unsigned char> seal(
    const SodiumBuffer& message,
    const std::vector<unsigned char>& publicKey,
    const std::string& postDecryptionInstructionsJson = ""
  );

  /**
   * @brief *Avoid Using* Seal a message using a raw libsodium public key.
   * 
   * Instead of using this static method, we recommend you use the seal
   * method on an instance of a PublicKey object.
   * This static method is used internally to libsodium's seal operation.
   * We have exposed so that others can replicate the internals of this class
   * if necessary, but recommend that only when there are reasons not to call
   * the non-static seal operation on an instance of this class.
   * 
   * @param message The plaintext message to seal
   * @param messageLength The length of the plaintext message to seal (in bytes)
   * @param publicKey The public key matching the private key used to unseal it.
   * @param postDecryptionInstructionsJson If this optional string is
   * passed, the same string must be passed to unseal the message.
   * RefPDI.
   * @return const std::vector<unsigned char> The sealed message (ciphertext)
   */
  static const std::vector<unsigned char> seal(
    const unsigned char* message,
    const size_t messageLength,
    const std::vector<unsigned char> &publicKey,
    const std::string &postDecryptionInstructionsJson = ""
  );

  /**
   * @brief Seal a plaintext message
   * 
   * @param message The plaintxt message to seal 
   * @param messageLength The length of the plaintext message in bytes
   * @param postDecryptionInstructionsJson If this optional string is
   * passed, the same string must be passed to unseal the message.
   * RefPDI.
   * @return const std::vector<unsigned char> 
   */
  const std::vector<unsigned char> seal(
    const unsigned char* message,
    const size_t messageLength,
    const std::string& postDecryptionInstructionsJson = ""
  ) const;

  /**
   * @copydoc PublicKey::seal(const unsigned char*,const size_t,const std::string&) const
   * 
   * @param message The plaintext message to seal
   * @param postDecryptionInstructionsJson If this optional string is
   * passed, the same string must be passed to unseal the message.
   * RefPDI.
   * @return const std::vector<unsigned char> 
   */
  const std::vector<unsigned char> seal(
    const SodiumBuffer &message,
    const std::string &postDecryptionInstructionsJson = ""
  ) const;

  /**
   * @brief Get the copy of the raw public key bytes used by lib-sodium
   * 
   * @return const std::vector<unsigned char> 
   */
  const std::vector<unsigned char> getPublicKeyBytes() const;

  /**
   * @brief Get the JSON-formatted key-derivation options string used to generate
   * the public-private key pair.
   * 
   * @return const std::string 
   */
  const std::string getKeyDerivationOptionsJson() const {
    return keyDerivationOptionsJson; 
  }

};

