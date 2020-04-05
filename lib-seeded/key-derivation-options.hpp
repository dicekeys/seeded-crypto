#pragma once

#pragma warning( disable : 26812 )
#include <cassert>
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "./externally-generated/key-derivation-parameters.hpp"
#include "hash-functions.hpp"

/**
 * Exception classes for key derivation
 */

// class KeyUseRestrictions {
// public:
// 	std::vector<std::string> androidPackagePrefixesAllowed;
//   	std::vector<std::string> urlPrefixesAllowed;

// 	KeyUseRestrictions(
// 		std::vector<std::string> androidPackagePrefixesAllowed,
// 	  	std::vector<std::string> urlPrefixesAllowed
// 	);

// 	KeyUseRestrictions(
// 		const nlohmann::json keyUseRestrictionsObject
// 	);

// };


/**
 * This class represents key generation options,
 * provided in JSON format, as an immutable class.
 */
class KeyDerivationOptions {

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
//	KeyUseRestrictions* keyUseRestrictions;
//	std::vector<std::string> restrictToClientApplicationsIdPrefixes;
	HashFunction *hashFunctionImplementation;
//	bool includeOrientationOfFacesInKey;

	~KeyDerivationOptions();

	/**
	 * Create a KeyDerivationOptions class from the JSON representation
	 * of the key generation options.
	 **/
	KeyDerivationOptions(
		const std::string &keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::KeyType keyTypeExpected =
			KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_
	);


	// static KeyDerivationOptions fromJson(
	// 	const std::string &keyDerivationOptionsJson,
	// 	const KeyDerivationOptionsJson::KeyType keyTypeExpected =
	// 		KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_
	// );

	//const void validate(const std::string applicationId) const;

	//KeyDerivationOptions(
	//	const std::string &keyDerivationOptionsJson,
	//	//const std::string applicationId,
	//	const KeyDerivationOptionsJson::KeyType keyTypeExpected = KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_
	//) : KeyDerivationOptions(keyDerivationOptionsJson, keyTypeExpected) {
	//	//validate(applicationId);
	//}


	const std::string keyDerivationOptionsJsonWithAllOptionalParametersSpecified(
		int indent = -1,
	  const char indent_char = ' '
	) const;

};
