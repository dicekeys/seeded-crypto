#pragma once

#ifndef EMSCRIPTEN
 #pragma warning( disable : 26812 )
#endif
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "./externally-generated/derivation-parameters.hpp"
#include "hash-functions.hpp"

/**
 * @brief This class parses a derivationOptionsJson string
 * on construction and then exposes the
 * @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
 * as fields of this class.
 * 
 * @ingroup BuildingBlocks
 */
class DerivationOptions {
/**
 * This class represents key generation options,
 * provided in JSON format, as an immutable class.
 */

private:
	nlohmann::json derivationOptionsExplicit;
public:
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
	 */
	DerivationOptionsJson::Algorithm algorithm;
	/**
	 * @brief The original JSON string used to construct this object
	 */
	const std::string derivationOptionsJson;

	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
	 */
	DerivationOptionsJson::type type;

	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
	 */
  	unsigned int lengthInBytes;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
	 */
	size_t hashFunctionMemoryLimitInBytes;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
	 */
	size_t hashFunctionMemoryPasses;

	/**
	 * @brief The name of the hash function specified in the @ref derivation_options_universal_fields "Derivation Options JSON Universal Fields"
	 */
	DerivationOptionsJson::HashFunction hashFunction;

	/**
	 * @brief A pointer to a hash function that *implements* the specified
	 * derivation hash function.
	 */
	HashFunction *hashFunctionImplementation;

	~DerivationOptions();

	/**
	 * Create a DerivationOptions class from the JSON representation
	 * of the key generation options.
	 * 
	 * @param derivationOptionsJson The JSON formatted key-deriation object to parse
	 * as specified by @ref derivation_options_format
	 * @param typeExpected The expected type, which will be the default if the JSON doesn't
	 * contain a type field and which will cause an exception to be thrown if the
	 * JSON has a conflicting type.  If not set
	 * (default: DerivationOptionsJson::type::_INVALID_TYPE_)
	 * there is no default type.
	 * @throws InvalidDerivationOptionsJsonException
	 * @throws InvalidDerivationOptionValueException
	 **/
	DerivationOptions(
		const std::string& derivationOptionsJson,
		const DerivationOptionsJson::type typeExpected =
			DerivationOptionsJson::type::_INVALID_TYPE_
	);

	/**
	 * @brief Return JSON with default parameters filled in.
	 *
	 * @param indent JSON indent ddpth
	 * @param indent_char The char used for JSON indenting
	 */
	const std::string derivationOptionsJsonWithAllOptionalParametersSpecified(
		int indent = -1,
	  const char indent_char = ' '
	) const;

	/**
	 * @brief This function derives the master secrets for SymmetricKey,
	 * for the SealingKey and UnsealingKey pair,
	 * for the SignatureVerificationKey and SigningKey pair,
	 * and for the general-purpose Secret class.
	 * 
	 * It applies the hash function specified in the derivationOptionsJson
	 * to a preimage of the following form:
	 * ```
	 *   <seedString> + '\0' + <typeRequired> + <derivationOptionsJson>
	 * ```
	 * where typeRequired is converted to a string in
	 * ["Secret", "SymmetricKey", "UnsealingKey", "SigningKey"],
	 * based on the value of the typeRequired parameter.
	 * 
	 *   * For "Secret", the generated secret is placed directly into the
	 *     `secretBytes` field of the Secret class.
	 *   * For "SymmetricKey", the generated secret becomes the `keyBytes` field
	 *     of the SymmetricKey class.
	 *   * For "UnsealingKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_box_seed_keypair` function, which generates
	 *     the key bytes for the UnsealingKey and SealingKey.
	 *   * For "SigningKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_sign_seed_keypair` function, which generates
	 *     the key bytes for the SigningKey and SignatureVerificationKey..
	 * 
	 * @param seedString A seed value that is the primary salt for the hash function
	 * @param derivationOptionsJson The derivation options in @ref derivation_options_format.
	 * @param typeRequired If the derivationOptionsJson has a type field, and that field
	 * specifies a value other than this typeRequired value, this function will throw an
	 * InvalidDerivationOptionValueException.
	 * @param lengthInBytesRequired If the derivationOptionsJson does not specify a lengthInBytes,
	 * generate a secret of this length. Throw an InvalidDerivationOptionValueException is
	 * the lengthInBytes it specifies does not match this value.
	 * @return const SodiumBuffer The derived secret, set to always be a const so that it is never
	 * modified directly.
	 * 
	 * @throw InvalidDerivationOptionValueException
	 * @throw InvalidDerivationOptionsJsonException
	 */
	static const SodiumBuffer deriveMasterSecret(
		const std::string& seedString,
		const std::string& derivationOptionsJson,
		const DerivationOptionsJson::type typeRequired,
		const size_t lengthInBytesRequired = 0
	);

	/**
	 * @brief This function derives the master secrets for SymmetricKey,
	 * for the SealingKey and UnsealingKey pair,
	 * for the SignatureVerificationKey and SigningKey pair,
	 * and for the general-purpose Secret class.
	 * 
	 * It applies the hash function specified in the derivationOptionsJson
	 * to a preimage of the following form:
	 * ```
	 *   <seedString> + '\0' + <type> + <derivationOptionsJson>
	 * ```
	 * where type is converted to a string in
	 * ["Secret", "SymmetricKey", "UnsealingKey", "SigningKey"],
	 * based on the value of the type parameter,
	 * defaultType if type is not set (_INVALID_TYPE_),
	 * or "" if neither is set (both are _INVALID_TYPE_).
	 * 
	 *   * For "Secret", the generated secret is placed directly into the
	 *     `secretBytes` field of the Secret class.
	 *   * For "SymmetricKey", the generated secret becomes the `keyBytes` field
	 *     of the SymmetricKey class.
	 *   * For "UnsealingKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_box_seed_keypair` function, which generates
	 *     the key bytes for the UnsealingKey and SealingKey.
	 *   * For "SigningKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_sign_seed_keypair` function, which generates
	 *     the key bytes for the SigningKey and SignatureVerificationKey..
	 * 
	 * @param seedString A seed value that is the primary salt for the hash function
	 * @param defaultType If the derivationOptionsJson has a type field, and that field
	 * specifies a value other than this typeRequired value, this function will throw an
	 * InvalidDerivationOptionValueException.
	 * @return const SodiumBuffer The derived secret, set to always be a const so that it is never
	 * modified directly.
	 * 
	 * @throw InvalidDerivationOptionValueException
	 */
	const SodiumBuffer deriveMasterSecret(
		const std::string& seedString,
		const DerivationOptionsJson::type defaultType =
			DerivationOptionsJson::type::_INVALID_TYPE_
	) const;

};
