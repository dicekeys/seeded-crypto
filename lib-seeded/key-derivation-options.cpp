#include <cassert>
#include <exception>
#include "sodium.h"
#pragma warning( disable : 26812 )


#include "key-derivation-options.hpp"
#include "exceptions.hpp"

KeyDerivationOptions::~KeyDerivationOptions() {
  if (hashFunctionImplementation) {
    delete hashFunctionImplementation;
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
  const std::string& _keyDerivationOptionsJson,
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

	if (keyType == KeyDerivationOptionsJson::KeyType::Secret) {
		keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::keyLengthInBytes] = keyLengthInBytes;
	}

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

    if (hashFunction == KeyDerivationOptionsJson::HashFunction::SHA256) {
      hashFunctionImplementation = new HashFunctionSHA256();
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::BLAKE2b) {
      hashFunctionImplementation = new HashFunctionBlake2b();
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id) {
      hashFunctionImplementation = new HashFunctionArgon2id(hashFunctionIterations, hashFunctionMemoryLimit);
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::Scrypt) {
      hashFunctionImplementation = new HashFunctionScrypt(hashFunctionIterations, hashFunctionMemoryLimit);
    } else {
      throw std::invalid_argument("Invalid hashFunction");
    }
}


const std::string KeyDerivationOptions::keyDerivationOptionsJsonWithAllOptionalParametersSpecified(
  int indent,
  const char indent_char
) const {
  return keyDerivationOptionsExplicit.dump(indent, indent_char);
}


const SodiumBuffer KeyDerivationOptions::deriveMasterSecret(
  const std::string& seedString,
  const KeyDerivationOptionsJson::KeyType defaultKeyType
) const {
  const KeyDerivationOptionsJson::KeyType finalKeyType =
    keyType == KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_ ?
      defaultKeyType : keyType;
  const std::string keyTypeString =
    finalKeyType == KeyDerivationOptionsJson::KeyType::Secret ? "Secret" :
		finalKeyType == KeyDerivationOptionsJson::KeyType::Symmetric ? "Symmetric" :
		finalKeyType == KeyDerivationOptionsJson::KeyType::Public ? "Public" :
		finalKeyType == KeyDerivationOptionsJson::KeyType::Signing ? "Signing" :
    "";

  // Create a hash preimage that is the seed string, followed by a null
  // terminator, followed by the keyDerivationOptionsJson string.
  //   <seedString> + '\0' <keyDerivationOptionsJson>
  SodiumBuffer preimage(
    // length of the seed string
    seedString.length() +
    // 1 character for a null char between the two strings
    1 +
    // length of key type
    keyTypeString.length() +
    // length of the json string specifying the key-derivation options
    keyDerivationOptionsJson.length()
  );

  // Use this moving pointer to write the primage
  unsigned char* primageWritePtr = preimage.data;
  // Copy the seed string into the preimage
  memcpy(
    primageWritePtr,
    seedString.c_str(),
    seedString.length()
  );
  primageWritePtr += seedString.length();
  // copy the null terminator between strings into the preimage
  *(primageWritePtr++) = '0';
  // copy the key type
  memcpy(
    primageWritePtr,
    keyTypeString.c_str(),
    keyTypeString.length()
  );
  primageWritePtr += keyTypeString.length();
  // copy the key derivation options into the preimage
  memcpy(
    primageWritePtr,
    keyDerivationOptionsJson.c_str(),
    keyDerivationOptionsJson.length()
  );

  // Hash the preimage to create the seed
  SodiumBuffer derivedKey =
    hashFunctionImplementation->hash(
        preimage.data,
        preimage.length,
        keyLengthInBytes
    );

  return derivedKey;
}

const SodiumBuffer KeyDerivationOptions::deriveMasterSecret(
		const std::string& seedString,
		const std::string& keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::KeyType keyTypeRequired,
		const size_t keyLengthInBytesRequired
	) {
    const KeyDerivationOptions keyDerivationOptions(keyDerivationOptionsJson,keyTypeRequired);
    // Ensure that the keyType in the key derivation options matches the requirement
    if (
      keyTypeRequired != KeyDerivationOptionsJson::KeyType::_INVALID_KEYTYPE_ &&
      keyTypeRequired != keyDerivationOptions.keyType  
    ) {
      throw InvalidKeyDerivationOptionValueException( (
        "Key generation options must have keyType " + std::to_string(keyTypeRequired)
      ).c_str() );
    }

    // Verify key-length requirements (if specified)
    if (keyLengthInBytesRequired > 0 &&
        keyDerivationOptions.keyLengthInBytes != keyLengthInBytesRequired) {
      throw InvalidKeyDerivationOptionValueException( (
        "Key length in bytes for this keyType should be " + std::to_string(keyLengthInBytesRequired) +
        " but keyLengthInBytes field was set to " + std::to_string(keyDerivationOptions.keyLengthInBytes)
        ).c_str()
      );
    }

    return keyDerivationOptions.deriveMasterSecret(seedString, keyTypeRequired);
  }