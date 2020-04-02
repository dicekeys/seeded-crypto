#include <cassert>
#include <exception>
#include "sodium.h"
#pragma warning( disable : 26812 )


#include "key-derivation-options.hpp"

// KeyUseRestrictions::KeyUseRestrictions(
//   std::vector<std::string> _androidPackagePrefixesAllowed,
//   std::vector<std::string> _urlPrefixesAllowed
// ) :
//   androidPackagePrefixesAllowed(_androidPackagePrefixesAllowed),
//   urlPrefixesAllowed(_urlPrefixesAllowed)
//   {}

// KeyUseRestrictions::KeyUseRestrictions(
//   const nlohmann::json keyUseRestrictionsObject
// ) : KeyUseRestrictions(
//   keyUseRestrictionsObject.value<std::vector<std::string>>(KeyUseRestrictionsJson::FieldNames::androidPackagePrefixesAllowed, std::vector<std::string>()),
//   keyUseRestrictionsObject.value<std::vector<std::string>>(KeyUseRestrictionsJson::FieldNames::urlPrefixesAllowed, std::vector<std::string>())
// ) {}

KeyDerivationOptions::~KeyDerivationOptions() {
  if (hashFunctionImplemenation) {
    delete hashFunctionImplemenation;
  }
  // if (keyUseRestrictions) {
  //   delete keyUseRestrictions;
  // }
}

// Wrap json parser in a function that throws exceptions as
// InvalidKeyDerivationOptionsJsonException
nlohmann::json parseJsonWithKeyDerviationOptionsExceptions(std::string json) {
  try {
    return nlohmann::json::parse(json);
  } catch (nlohmann::json::exception e) {
    throw InvalidKeyDerivationOptionsJsonException(e.what());
  } catch (...) {
    throw InvalidKeyDerivationOptionsJsonException();
  }
}

// Use the nlohmann::json library to read the JSON-encoded
// key generation options.
// We make heavy use of the library's enum conversion, as documented at:
//   https://github.com/nlohmann/json#specializing-enum-conversion
KeyDerivationOptions::KeyDerivationOptions(
  const std::string &_keyDerivationOptionsJson,
  const KeyDerivationOptionsJson::KeyType keyTypeExpected
) : keyDerivationOptionsJson(_keyDerivationOptionsJson) {
  const nlohmann::json& keyDerivationOptionsObject = parseJsonWithKeyDerviationOptionsExceptions(
    keyDerivationOptionsJson.size() == 0 ? "{}" : keyDerivationOptionsJson
  );

  //
  // keyType
  //
  keyType = keyDerivationOptionsObject.value<KeyDerivationOptionsJson::KeyType>(
      KeyDerivationOptionsJson::FieldNames::keyType,
      keyTypeExpected
    );

  if (keyTypeExpected != KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_ &&
      keyType != keyTypeExpected) {
    // We were expecting keyType == keyTypeExpected since keyTypeExpected wasn't invalid,
    // but the JSON specified a different key type
    throw InvalidKeyDerivationOptionValueException("Unexpected keyType in KeyDerivationOptions");
  }

  if (keyType == KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_) {
    // No valid keyType was specified
    throw InvalidKeyDerivationOptionValueException("Invalid keyType in KeyDerivationOptions");
  }
  keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::keyType] = keyType;

  //
  // algorithm
  //
  algorithm = keyDerivationOptionsObject.value<KeyDerivationOptionsJson::Algorithm>(
    KeyDerivationOptionsJson::FieldNames::algorithm,
    // Default value depends on the purpose
    (keyType == KeyDerivationOptionsJson::KeyType::Symmetric) ?
        // For symmetric crypto, default to XSalsa20Poly1305
        KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305 :
    (keyType == KeyDerivationOptionsJson::KeyType::Public) ?
      // For public key crypto, default to X25519
      KeyDerivationOptionsJson::Algorithm::X25519 :
    (keyType == KeyDerivationOptionsJson::KeyType::Signing) ?
      // For public key signing, default to Ed25519
    KeyDerivationOptionsJson::Algorithm::Ed25519 :
      // Otherwise, the leave the key setting to invalid (we don't care about a specific key type)
      KeyDerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_
  );

  // Validate that the key type is allowed for this keyType
  if (keyType == KeyDerivationOptionsJson::KeyType::Symmetric &&
      algorithm != KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305
  ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for symmetric key cryptography"
    );
  }

  if (keyType == KeyDerivationOptionsJson::KeyType::Public &&
    algorithm != KeyDerivationOptionsJson::Algorithm::X25519
    ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for public key cryptography"
    );
  }
  if (keyType == KeyDerivationOptionsJson::KeyType::Signing &&
    algorithm != KeyDerivationOptionsJson::Algorithm::Ed25519
    ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for signing key"
    );
  }

  if (keyType != KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_) {
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::keyType] = keyType;
  }

  if (algorithm != KeyDerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_) {
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::algorithm] = algorithm;
  }

  //
  // keyLengthInBytes
  //
  keyLengthInBytes =
    keyDerivationOptionsObject.value<unsigned int>(
      KeyDerivationOptionsJson::FieldNames::keyLengthInBytes,
      algorithm == KeyDerivationOptionsJson::Algorithm::X25519 ?
        crypto_box_SEEDBYTES :
      algorithm == KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305 ?
        // When a 256-bit (32 byte) key is needed, default to 32 bytes
        crypto_stream_xsalsa20_KEYBYTES :
        // When the key type is not defined, default to 32 bytes. 
        32
    );

  if (
    algorithm == KeyDerivationOptionsJson::Algorithm::X25519
    && keyLengthInBytes != crypto_box_SEEDBYTES
  ) {
    throw InvalidKeyDerivationOptionValueException( (
        "X25519 public key cryptography must use keyLengthInBytes of " +
        std::to_string(crypto_box_SEEDBYTES)
      ).c_str() );
  }
  if (
    algorithm == KeyDerivationOptionsJson::Algorithm::Ed25519
    && keyLengthInBytes != crypto_sign_SEEDBYTES
    ) {
    throw InvalidKeyDerivationOptionValueException((
      "Ed25519 signing must use keyLengthInBytes of " +
      std::to_string(crypto_sign_SEEDBYTES)
      ).c_str());
  }
  if (
    algorithm == KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305 &&
    keyLengthInBytes != crypto_stream_xsalsa20_KEYBYTES
  ) {
    throw InvalidKeyDerivationOptionValueException( (
        "XSalsa20Poly1305 symmetric cryptography must use keyLengthInBytes of " +
        std::to_string(crypto_stream_xsalsa20_KEYBYTES)
      ).c_str() );
  }

	if (keyType == KeyDerivationOptionsJson::KeyType::Seed) {
		keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::keyLengthInBytes] = keyLengthInBytes;
	}

  // if (keyDerivationOptionsObject.contains(KeyDerivationOptionsJson::FieldNames::restrictions)) {
  //   keyUseRestrictions = new KeyUseRestrictions(keyDerivationOptionsObject.at(KeyDerivationOptionsJson::FieldNames::restrictions));
  // } else {
  //   keyUseRestrictions = NULL;
  // }
  // if (keyUseRestrictions) {
  //   keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::restrictions] = nlohmann::json({
  //     {KeyUseRestrictionsJson::FieldNames::androidPackagePrefixesAllowed, keyUseRestrictions->androidPackagePrefixesAllowed },
  //     {KeyUseRestrictionsJson::FieldNames::urlPrefixesAllowed, keyUseRestrictions->urlPrefixesAllowed }
  //   });
  // }

  hashFunction = keyDerivationOptionsObject.value<KeyDerivationOptionsJson::HashFunction>(
      KeyDerivationOptionsJson::FieldNames::hashFunction,
      KeyDerivationOptionsJson::HashFunction::SHA256
  );
  keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunction] = hashFunction;
  hashFunctionIterations = keyDerivationOptionsObject.value<size_t>(
    KeyDerivationOptionsJson::FieldNames::hashFunctionIterations,
    (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id || hashFunction == KeyDerivationOptionsJson::HashFunction::Scrypt) ? 2 : 1
  );
  hashFunctionMemoryLimit = keyDerivationOptionsObject.value<size_t>(
    KeyDerivationOptionsJson::FieldNames::hashFunctionMemoryLimit, 67108864U
  );
  if (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id || hashFunction == KeyDerivationOptionsJson::HashFunction::Scrypt) {
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunctionMemoryLimit] = hashFunctionMemoryLimit;
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunctionIterations] = hashFunctionIterations;
  }

  //
  // hashFunction
  //
  // if (!keyDerivationOptionsObject.contains(KeyDerivationOptionsJson::FieldNames::hashFunction)) {
  //   hashFunction = new HashFunctionSHA256();    
  //   keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunction] = KeyDerivationOptionsJson::HashFunction::SHA256;
  // } else {
  //   const auto jhashFunction = keyDerivationOptionsObject.at(KeyDerivationOptionsJson::FieldNames::hashFunction);
  //   keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunction] = jhashFunction;
    if (hashFunction == KeyDerivationOptionsJson::HashFunction::SHA256) {
      hashFunctionImplemenation = new HashFunctionSHA256();
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::BLAKE2b) {
      hashFunctionImplemenation = new HashFunctionBlake2b();
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id) {
      hashFunctionImplemenation = new HashFunctionArgon2id(hashFunctionIterations, hashFunctionMemoryLimit);
    } else if (algorithm == KeyDerivationOptionsJson::HashFunction::Scrypt) {
      hashFunctionImplemenation = new HashFunctionScrypt(hashFunctionIterations, hashFunctionMemoryLimit);
    } else {
      throw std::invalid_argument("Invalid hashFunction");
    }

  //
  // includeOrientationOfFacesInKey
  //
  // includeOrientationOfFacesInKey = keyDerivationOptionsObject.value<bool>(
  //   KeyDerivationOptionsJson::FieldNames::includeOrientationOfFacesInKey,
  //   true
  // );
  // keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::includeOrientationOfFacesInKey] =
  //   includeOrientationOfFacesInKey;
  //
  // additionalSalt
  //
  // There's no need to read in the additionalSalt string, as it's already part
  // of the KeyDerivationOptions json string from which keys are generated.
  // const string additionalSalt = keyDerivationOptionsObject.value<std::string>(
  // 		KeyDerivationOptionsJson::FieldNames::additionalSalt, "");
  // if (keyDerivationOptionsObject.contains(KeyDerivationOptionsJson::FieldNames::additionalSalt)) {
  //   keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::additionalSalt] =
  //     keyDerivationOptionsObject[KeyDerivationOptionsJson::FieldNames::additionalSalt];
  // }

};


// const void KeyDerivationOptions::validate(
//   const std::string applicationId
// ) const {
//   if (restrictToClientApplicationsIdPrefixes.size() > 0) {
//     bool prefixFound = false;
//     for (const std::string prefix : restrictToClientApplicationsIdPrefixes) {
//       if (applicationId.substr(0, prefix.length()) == prefix) {
//         prefixFound = true;
//         break;
//       }
//     }
//     if (!prefixFound) {
//       throw ClientNotAuthorizedException();
//     }
//     bool noneMatched = true;
//   }
// }



const std::string KeyDerivationOptions::keyDerivationOptionsJsonWithAllOptionalParametersSpecified(
  int indent,
  const char indent_char
) const {
  return keyDerivationOptionsExplicit.dump(indent, indent_char);
}
