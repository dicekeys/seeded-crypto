#pragma once

#include "sodium-buffer.hpp"
#include "signature-verification-key.hpp"

/**
 * @brief SigningKeys generate _signatures_ of messages which can then be
 * used by the corresponding SignatureVerificationKey to verify that a message
 * was signed by  can confirm that the message was indeed signed by the
 * SigningKey and has not since been tampered with.
 *
 * The corresponding SignatureVerificationKey can be obtained by calling
 * getSignatureVerificationKey.
 * 
 * The key pair of the SigningKey and SignatureVerificationKey is generated
 * from a seed and a set of key-derivation specified options in
 *  @ref key_derivation_options_format.
 * 
 * @ingroup DerivedFromSeeds
 */
class SigningKey {
protected:
  /**
   * @brief _May_ store the byte representation of this SigningKey's
   * corresponding SignatureVerificationKey.
   * 
   * When a signing key is generated, it's corresponding signature-verification
   * key is generated with it. However, it can also be re-generated from the
   * signature-verification key. Thus, storing the signature-verification key
   * is more a matter of efficiency than necessity.  We store it by default.
   * 
   * However, when a SigningKey is encoded into JSON format, the default
   * representation elides the verificaiton key since it can be re-generated
   * if needed so that the encoding is more compact. If this signing-key
   * is reconsistuted from JSON format, the signatureVerificationKeyBytes
   * will be empty (a zero-length vector) and it will only be re-generated
   * when getSignatureVerificationKeyBytes() is called.
   */
  std::vector<unsigned char> signatureVerificationKeyBytes;

public:
  /**
   * @brief The raw binary representation of the cryptographic signing key.
   */
  const SodiumBuffer signingKeyBytes;
  /**
   * @brief A @ref key_derivation_options_format string used to specify how this key is derived.
   */
  const std::string keyDerivationOptionsJson;

  /**
   * @brief Construct a copy of another SigningKey
   */
  SigningKey(
    const SigningKey& other
  );

  /**
   * @brief Construct from the objects members, excluding the
   * signature-verification key (which can be re-generated if needed)
   */
  SigningKey(
    const SodiumBuffer &signingKeyBytes,
    const std::string& KeyDerivationOptionsJson
  );

  /**
   * @brief Construct from the objects members, excluding the
   * signature-verification key
   */
  SigningKey(
    const SodiumBuffer &signingKeyBytes,
    const std::vector<unsigned char> &signatureVerificationKeyBytes,
    const std::string& keyDerivationOptionsJson
  );

    /**
   * @brief Construct a new SigningKey by deriving a signing key pair from a seed
   * string and a set of key-derivation options in @ref key_derivation_options_format.
   * 
   * @param seedString The private seed which is used to generate the key pair.
   * Anyone who knows (or can guess) this seed can re-generate the key pair
   * by passing it along with the keyDerivationOptionsJson.
   * @param keyDerivationOptionsJson The key-derivation options in @ref key_derivation_options_format.
   */
  SigningKey(
    const std::string& seedString,
    const std::string& keyDerivationOptionsJson
  );

  /**
   * @brief Construct (reconsitute) the SigningKey from JSON format.
   * The JSON object may or may not contain the signatureVerificationKeyBytes.
   * If it does not, an empty byte vector will be stored and the verification
   * key bytes will be re-derived from the signing key by
   * getSignatureVerificationKeyBytes if they are needed.
   * 
   * @param signingKeyAsJson 

   */
  static SigningKey fromJson(
   const std::string& signingKeyAsJson
  );

  /**
   * @brief Get the raw binary representation of the signature-verification key,
   * re-deriving them from the signing key if signatureVerificationKeyBytes is a
   * zero-length vector
   */
  const std::vector<unsigned char> getSignatureVerificationKeyBytes();

  /**
   * @brief Get a SignatureVerificationKey which is used to verify
   * signatures generated with this SigningKey.
   */
  const SignatureVerificationKey getSignatureVerificationKey();

  /**
   * @brief Generate a signature for a message which can be used
   * by the corresponding public SignatureVerificationKey to verify that
   * this message was, in fact, signed by this key.
   * 
   * @param message The message to _sign_ by generating the signature 
   * @param messageLength The length of the message.
   * @return const std::vector<unsigned char> A signature, which can
   * be used with the SignatureVerificationKey to prove that this
   * act of signing (this call to generateSignature) took place.
   */
  const std::vector<unsigned char> generateSignature(
    const unsigned char* message,
    const size_t messageLength
  ) const;

  /**
   * @brief Generate a signature for a message, which can be used
   * by the corresponding public SignatureVerificationKey to verify that
   * this message was, in fact, signed by this key.
   * 
   * @param message The message to _sign_ by generating the signature 
   * @return const std::vector<unsigned char> A signature, which can
   * be used with the SignatureVerificationKey to prove that this
   * act of signing (this call to generateSignature) took place.
   */
  const std::vector<unsigned char> generateSignature(
    const std::vector<unsigned char> &message
  ) const;

  /**
   * @brief Serialize this object to a JSON-formatted string
   * 
   * It can be reconstituted by calling the constructor with this string.
   * 
   * @param minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater
   * The JSON-encoding will always include the binary signing key bytes (in hex format)
   * and the keyDerviationOptionsJson used to derive the key, but the
   * signature-verification key bytes will not be included unless you set
   * this value to false. Rather, if it is elided, the signature-verification key
   * can be reconstituted from the signing-key after the object is reconstituted,
   * which takes a little computation in return for the space saved in the JSON format.
   * @param indent The number of characters to indent the JSON (optional)
   * @param indent_char The character with which to indent the JSON (optional)
   * @return const std::string
   */
  const std::string toJson(
    bool minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater = true,
    int indent = -1,
    const char indent_char = ' '
  ) const;

  /**
   * @brief Serialize to byte array as a list of:
   *   (keyBytes, signatureVerificationKeyBytes, keyDerivationOptionsJson)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   *
   * @param minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater
   * If set to true (the default), an empty buffer will be passed for the 
   * signatureVerificationKeyBytes. After the object is deserialized, the
   * replica can re-generate a signature-verification key from the signing key,
   * which takes a little computation in return for the 28 bytes saved in this format.
   */
  const SodiumBuffer toSerializedBinaryForm(
    bool minimizeSizeByRemovingTheSignatureVerificationKeyBytesWhichCanBeRegeneratedLater = true
  ) const;

  /**
   * @brief Deserialize from a byte array stored as a list of:
   *   (keyBytes, signatureVerificationKeyBytes, keyDerivationOptionsJson)
   * 
   * Stored in SodiumBuffer's fixed-length list format.
   * Strings are stored as UTF8 byte arrays.
   */
  static SigningKey fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm);


};
