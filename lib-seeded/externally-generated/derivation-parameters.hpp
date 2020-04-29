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

namespace DerivationOptionsJson {
	namespace FieldNames {
		const std::string algorithm = "algorithm";
		const std::string hashFunction = "hashFunction";
		const std::string hashFunctionMemoryLimitInBytes = "hashFunctionMemoryLimitInBytes";
		const std::string hashFunctionMemoryPasses = "hashFunctionMemoryPasses";
		const std::string lengthInBytes = "lengthInBytes";
		const std::string type = "type";
		const std::string restrictions = "restrictions";
		const std::string excludeOrientationOfFaces = "excludeOrientationOfFaces";
	}

	enum type {
		_INVALID_TYPE_ = 0,
		Secret,
		SymmetricKey,
		UnsealingKey,
		SigningKey
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( type, {
		{type::_INVALID_TYPE_, nullptr},
		{type::Secret, "Secret"},
		{type::SymmetricKey, "SymmetricKey"},
		{type::UnsealingKey, "UnsealingKey"},
		{type::SigningKey, "SigningKey"}
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
	const unsigned long long hashFunctionMemoryPasses = 2;
	const size_t hashFunctionMemoryLimitInBytes = 67108864;
}

namespace DecryptionRestrictionsJson {
	namespace FieldNames {
		const std::string androidPackagePrefixesAllowed = "androidPackagePrefixesAllowed";
		const std::string urlPrefixesAllowed = "urlPrefixesAllowed";
		const std::string userMustAcknowledgeThisMessage = "userMustAcknowledgeThisMessage";
		const std::string alsoPostToUrl = "alsoPostToUrl";
		const std::string onlyPostToUrl = "onlyPostToUrl";
		const std::string reEncryptWithSealingKey = "reEncryptWithSealingKey";
	}
};


