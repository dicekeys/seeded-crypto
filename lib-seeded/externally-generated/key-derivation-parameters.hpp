//////////////////////////////////////////////////////////////////
// KeyDerivationOptions JSON Specification
// - Automatically-generated file - NOT TO BE MODIFIED DIRECTLY
//////////////////////////////////////////////////////////////////
//
// This c++ header file specifies the JSON parameter names
// for KeyDerivationOptions.
#pragma once

#include <string>

namespace KeyUseRestrictionsJson {
	namespace FieldNames {
		const std::string androidPackagePrefixesAllowed = "androidPackagePrefixesAllowed";
		const std::string urlPrefixesAllowed = "urlPrefixesAllowed";
	}
}

namespace KeyDerivationOptionsJson {
	namespace FieldNames {
		const std::string algorithm = "algorithm";
		const std::string hashFunction = "hashFunction";
		const std::string hashFunctionMemoryLimit = "hashFunctionMemoryLimit";
		const std::string hashFunctionIterations = "hashFunctionIterations";
		const std::string keyLengthInBytes = "keyLengthInBytes";
		const std::string keyType = "keyType";
		const std::string restrictions = "restrictions";
	}

	enum KeyType {
		_INVALID_KEYTYPE_ = 0,
		Seed,
		Symmetric,
		Public,
		Signing
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( KeyType, {
		{KeyType::_INVALID_KEYTYPE_, nullptr},
		{KeyType::Seed, "Seed"},
		{KeyType::Symmetric, "Symmetric"},
		{KeyType::Public, "Public"},
		{KeyType::Signing, "Signing"}
	})
	

	enum Algorithm {
		_INVALID_ALGORITHM_ = 0,
		XSalsa20Poly1305,
		X25519,
		Ed25519
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( Algorithm, {
		{Algorithm::_INVALID_ALGORITHM_, nullptr},
		{Algorithm::XSalsa20Poly1305, "XSalsa20Poly1305"},
		{Algorithm::X25519, "X25519"},
		{Algorithm::Ed25519, "Ed25519"}
	})
	

	enum HashFunction {
		_INVALID_HASHFUNCTION_ = 0,
		BLAKE2b,
		SHA256,
		Argon2id,
		Scrypt
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( HashFunction, {
		{HashFunction::_INVALID_HASHFUNCTION_, nullptr},
		{HashFunction::BLAKE2b, "BLAKE2b"},
		{HashFunction::SHA256, "SHA256"},
		{HashFunction::Argon2id, "Argon2id"},
		{HashFunction::Scrypt, "Scrypt"}
	})
	

};

namespace Argoin2idDefaults {
	const unsigned long long hashFunctionIterations = 2;
	const size_t hashFunctionMemoryLimit = 67108864;
}

namespace DecryptionRestrictionsJson {
	namespace FieldNames {
		const std::string androidPackagePrefixesAllowed = "androidPackagePrefixesAllowed";
		const std::string urlPrefixesAllowed = "urlPrefixesAllowed";
		const std::string userMustAcknowledgeThisMessage = "userMustAcknowledgeThisMessage";
		const std::string alsoPostToUrl = "alsoPostToUrl";
		const std::string onlyPostToUrl = "onlyPostToUrl";
		const std::string reEncryptWithPublicKey = "reEncryptWithPublicKey";
	}
};


