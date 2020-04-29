#pragma once

#pragma warning( disable : 26812 )
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "./externally-generated/key-derivation-parameters.hpp"
#include "hash-functions.hpp"

/**
 * @brief This class parses a keyDerivationOptionsJson string
 * on construction and then exposes the
 * @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
 * as fields of this class.
 * 
 * @ingroup BuildingBlocks
 */
class KeyDerivationOptions {
/**
 * This class represents key generation options,
 * provided in JSON format, as an immutable class.
 */

private:
	nlohmann::json keyDerivationOptionsExplicit;
public:
	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	KeyDerivationOptionsJson::Algorithm algorithm;
	/**
	 * @brief The original JSON string used to construct this object
	 */
	const std::string keyDerivationOptionsJson;

	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	KeyDerivationOptionsJson::type type;

	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
  	unsigned int lengthInBytes;
	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	size_t hashFunctionMemoryLimitInBytes;
	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	size_t hashFunctionMemoryPasses;

	/**
	 * @brief The name of the hash function specified in the @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	KeyDerivationOptionsJson::HashFunction hashFunction;

	/**
	 * @brief A pointer to a hash function that *implements* the specified
	 * key-derivation hash function.
	 */
	HashFunction *hashFunctionImplementation;

	~KeyDerivationOptions();

	/**
	 * Create a KeyDerivationOptions class from the JSON representation
	 * of the key generation options.
	 * 
	 * @param keyDerivationOptionsJson The JSON formatted key-deriation object to parse
	 * as specified by @ref key_derivation_options_format
	 * @param typeExpected The expected type, which will be the default if the JSON doesn't
	 * contain a type field and which will cause an exception to be thrown if the
	 * JSON has a conflicting type.  If not set
	 * (default: KeyDerivationOptionsJson::type::_INVALID_TYPE_)
	 * there is no default type.
	 * @throws InvalidKeyDerivationOptionsJsonException
	 * @throws InvalidKeyDerivationOptionValueException
	 **/
	KeyDerivationOptions(
		const std::string& keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::type typeExpected =
			KeyDerivationOptionsJson::type::_INVALID_TYPE_
	);

	/**
	 * @brief Return JSON with default parameters filled in.
	 *
	 * @param indent JSON indent ddpth
	 * @param indent_char The char used for JSON indenting
	 */
	const std::string keyDerivationOptionsJsonWithAllOptionalParametersSpecified(
		int indent = -1,
	  const char indent_char = ' '
	) const;

	/**
	 * @brief This function derives the master secrets for SymmetricKey,
	 * for the PublicKey and PrivateKey pair,
	 * for the SignatureVerificationKey and SigningKey pair,
	 * and for the general-purpose Secret class.
	 * 
	 * It applies the hash function specified in the keyDerivationOptionsJson
	 * to a preimage of the following form:
	 * ```
	 *   <seedString> + '\0' + <typeRequired> + <keyDerivationOptionsJson>
	 * ```
	 * where typeRequired is converted to a string in
	 * ["Secret", "Symmetric", "Public", "Signing"],
	 * based on the value of the typeRequired parameter.
	 * 
	 *   * For "Secret", the generated secret is placed directly into the
	 *     `secretBytes` field of the Secret class.
	 *   * For "Symmetric", the generated secret becomes the `keyBytes` field
	 *     of the SymmetricKey class.
	 *   * For "Public", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_box_seed_keypair` function, which generates
	 *     the key bytes for the PrivateKey and PublicKey.
	 *   * For "Signing", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_sign_seed_keypair` function, which generates
	 *     the key bytes for the SigningKey and SignatureVerificationKey..
	 * 
	 * @param seedString A seed value that is the primary salt for the hash function
	 * @param keyDerivationOptionsJson The key-derivation options in @ref key_derivation_options_format.
	 * @param typeRequired If the keyDerivationOptionsJson has a type field, and that field
	 * specifies a value other than this typeRequired value, this function will throw an
	 * InvalidKeyDerivationOptionValueException.
	 * @param lengthInBytesRequired If the keyDerivationOptionsJson does not specify a lengthInBytes,
	 * generate a secret of this length. Throw an InvalidKeyDerivationOptionValueException is
	 * the lengthInBytes it specifies does not match this value.
	 * @return const SodiumBuffer The derived secret, set to always be a const so that it is never
	 * modified directly.
	 * 
	 * @throw InvalidKeyDerivationOptionValueException
	 * @throw InvalidKeyDerivationOptionsJsonException
	 */
	static const SodiumBuffer deriveMasterSecret(
		const std::string& seedString,
		const std::string& keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::type typeRequired,
		const size_t lengthInBytesRequired = 0
	);

	/**
	 * @brief This function derives the master secrets for SymmetricKey,
	 * for the PublicKey and PrivateKey pair,
	 * for the SignatureVerificationKey and SigningKey pair,
	 * and for the general-purpose Secret class.
	 * 
	 * It applies the hash function specified in the keyDerivationOptionsJson
	 * to a preimage of the following form:
	 * ```
	 *   <seedString> + '\0' + <type> + <keyDerivationOptionsJson>
	 * ```
	 * where type is converted to a string in
	 * ["Secret", "Symmetric", "Public", "Signing"],
	 * based on the value of the type parameter,
	 * defaultType if type is not set (_INVALID_TYPE_),
	 * or "" if neither is set (both are _INVALID_TYPE_).
	 * 
	 *   * For "Secret", the generated secret is placed directly into the
	 *     `secretBytes` field of the Secret class.
	 *   * For "Symmetric", the generated secret becomes the `keyBytes` field
	 *     of the SymmetricKey class.
	 *   * For "Public", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_box_seed_keypair` function, which generates
	 *     the key bytes for the PrivateKey and PublicKey.
	 *   * For "Signing", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_sign_seed_keypair` function, which generates
	 *     the key bytes for the SigningKey and SignatureVerificationKey..
	 * 
	 * @param seedString A seed value that is the primary salt for the hash function
	 * @param defaultType If the keyDerivationOptionsJson has a type field, and that field
	 * specifies a value other than this typeRequired value, this function will throw an
	 * InvalidKeyDerivationOptionValueException.
	 * @return const SodiumBuffer The derived secret, set to always be a const so that it is never
	 * modified directly.
	 * 
	 * @throw InvalidKeyDerivationOptionValueException
	 */
	const SodiumBuffer deriveMasterSecret(
		const std::string& seedString,
		const KeyDerivationOptionsJson::type defaultType =
			KeyDerivationOptionsJson::type::_INVALID_TYPE_
	) const;

};
