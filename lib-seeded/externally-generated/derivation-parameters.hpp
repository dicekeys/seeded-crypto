//////////////////////////////////////////////////////////////////
// KeyDerivationOptions JSON Specification
// - Automatically-generated file - NOT TO BE MODIFIED DIRECTLY
//////////////////////////////////////////////////////////////////
//
// This c++ header file specifies the JSON parameter names
// for KeyDerivationOptions.
#pragma once

#include <string>

namespace DerivationOptionsJson {
	namespace FieldNames {
		const std::string androidPackagePrefixesAllowed = "androidPackagePrefixesAllowed";
		const std::string urlPrefixesAllowed = "urlPrefixesAllowed";
		const std::string requireAuthenticationHandshake = "requireAuthenticationHandshake";
		const std::string algorithm = "algorithm";
		const std::string hashFunction = "hashFunction";
		const std::string hashFunctionMemoryLimitInBytes = "hashFunctionMemoryLimitInBytes";
		const std::string hashFunctionMemoryPasses = "hashFunctionMemoryPasses";
		const std::string lengthInBits = "lengthInBits";
		const std::string lengthInChars = "lengthInChars";
		const std::string lengthInBytes = "lengthInBytes";
		const std::string lengthInWords = "lengthInWords";
		const std::string type = "type";
		const std::string excludeOrientationOfFaces = "excludeOrientationOfFaces";
		const std::string wordList = "wordList";

	}

	enum type {
		_INVALID_TYPE_ = 0,
		Password = 1,
		Secret = 2,
		SymmetricKey = 3,
		UnsealingKey = 4,
		SigningKey = 5
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( type, {
		{type::_INVALID_TYPE_, nullptr},
		{type::Password, "Password"},
		{type::Secret, "Secret"},
		{type::SymmetricKey, "SymmetricKey"},
		{type::UnsealingKey, "UnsealingKey"},
		{type::SigningKey, "SigningKey"},
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


	enum WordList {
		_INVALID_WORD_LIST_ = 0,
		EN_512_words_5_chars_max_ed_4_20200917,
		EN_1024_words_6_chars_max_ed_4_20200917
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( WordList, {
		{WordList::_INVALID_WORD_LIST_, nullptr},
		{WordList::EN_512_words_5_chars_max_ed_4_20200917, "EN_512_words_5_chars_max_ed_4_20200917"},
		{WordList::EN_1024_words_6_chars_max_ed_4_20200917, "EN_1024_words_6_chars_max_ed_4_20200917"}
	})
	


	enum HashFunction {
		_INVALID_HASHFUNCTION_ = 0,
		BLAKE2b,
		Argon2id,
	};
	NLOHMANN_JSON_SERIALIZE_ENUM( HashFunction, {
		{HashFunction::_INVALID_HASHFUNCTION_, nullptr},
		{HashFunction::BLAKE2b, "BLAKE2b"},
		{HashFunction::Argon2id, "Argon2id"},
	})
	

};

namespace Argon2idDefaults {
	const unsigned long long hashFunctionMemoryPasses = 2;
	const size_t hashFunctionMemoryLimitInBytes = 67108864;
}



