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
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	const std::string keyDerivationOptionsJson;

	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	KeyDerivationOptionsJson::KeyType keyType;

	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
  	unsigned int keyLengthInBytes;
	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	size_t hashFunctionMemoryLimit;
	/**
	 * @brief Mirroring the JSON field in @ref key_derivation_options_universal_fields "Key-Derivation Options JSON Universal Fields"
	 */
	size_t hashFunctionIterations;

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
	 * @param keyTypeExpected The expected keyType, which will be the default if the JSON doesn't
	 * contain a keyType field and which will cause an exception to be thrown if the
	 * JSON has a conflicting keyType.  If not set
	 * (default: KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_)
	 * there is no default keyType.
	 * @throws InvalidKeyDerivationOptionsJsonException
	 * @throws InvalidKeyDerivationOptionValueException
	 **/
	KeyDerivationOptions(
		const std::string& keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::KeyType keyTypeExpected =
			KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_
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

};
