#pragma once

#pragma warning( disable : 26812 )
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "./externally-generated/key-derivation-parameters.hpp"
#include "hash-functions.hpp"


class KeyDerivationOptions {
/**
 * This class represents key generation options,
 * provided in JSON format, as an immutable class.
 */

private:
	nlohmann::json keyDerivationOptionsExplicit;
public:
	KeyDerivationOptionsJson::Algorithm algorithm;
	const std::string keyDerivationOptionsJson;
	KeyDerivationOptionsJson::KeyType keyType;
  	unsigned int keyLengthInBytes;
	size_t hashFunctionMemoryLimit;
	size_t hashFunctionIterations;
	KeyDerivationOptionsJson::HashFunction hashFunction;
	HashFunction *hashFunctionImplementation;

	~KeyDerivationOptions();

	/**
	 * Create a KeyDerivationOptions class from the JSON representation
	 * of the key generation options.
	 **/
	KeyDerivationOptions(
		const std::string& keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::KeyType keyTypeExpected =
			KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_
	);

	const std::string keyDerivationOptionsJsonWithAllOptionalParametersSpecified(
		int indent = -1,
	  const char indent_char = ' '
	) const;

};
