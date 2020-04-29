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
  const KeyDerivationOptionsJson::type typeExpected
) : keyDerivationOptionsJson(_keyDerivationOptionsJson) {
  const nlohmann::json& keyDerivationOptionsObject = parseJsonWithKeyDerviationOptionsExceptions(
    keyDerivationOptionsJson.size() == 0 ? "{}" : keyDerivationOptionsJson
  );

  //
  // type
  //
  type = keyDerivationOptionsObject.value<KeyDerivationOptionsJson::type>(
      KeyDerivationOptionsJson::FieldNames::type,
      typeExpected
    );

  if (typeExpected != KeyDerivationOptionsJson::type::_INVALID_TYPE_ &&
      type != typeExpected) {
    // We were expecting type == typeExpected since typeExpected wasn't invalid,
    // but the JSON specified a different key type
    throw InvalidKeyDerivationOptionValueException("Unexpected type in KeyDerivationOptions");
  }

  if (type == KeyDerivationOptionsJson::type::_INVALID_TYPE_) {
    // No valid type was specified
    throw InvalidKeyDerivationOptionValueException("Invalid type in KeyDerivationOptions");
  }
  keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::type] = type;

  //
  // algorithm
  //
  algorithm = keyDerivationOptionsObject.value<KeyDerivationOptionsJson::Algorithm>(
    KeyDerivationOptionsJson::FieldNames::algorithm,
    // Default value depends on the purpose
    (type == KeyDerivationOptionsJson::type::Symmetric) ?
        // For symmetric crypto, default to XSalsa20Poly1305
        KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305 :
    (type == KeyDerivationOptionsJson::type::Public) ?
      // For public key crypto, default to X25519
      KeyDerivationOptionsJson::Algorithm::X25519 :
    (type == KeyDerivationOptionsJson::type::Signing) ?
      // For public key signing, default to Ed25519
    KeyDerivationOptionsJson::Algorithm::Ed25519 :
      // Otherwise, the leave the key setting to invalid (we don't care about a specific key type)
      KeyDerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_
  );

  // Validate that the key type is allowed for this type
  if (type == KeyDerivationOptionsJson::type::Symmetric &&
      algorithm != KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305
  ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for symmetric key cryptography"
    );
  }

  if (type == KeyDerivationOptionsJson::type::Public &&
    algorithm != KeyDerivationOptionsJson::Algorithm::X25519
    ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for public key cryptography"
    );
  }
  if (type == KeyDerivationOptionsJson::type::Signing &&
    algorithm != KeyDerivationOptionsJson::Algorithm::Ed25519
    ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for signing key"
    );
  }

  if (type != KeyDerivationOptionsJson::type::_INVALID_TYPE_) {
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::type] = type;
  }

  if (algorithm != KeyDerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_) {
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::algorithm] = algorithm;
  }

  //
  // lengthInBytes
  //
  lengthInBytes =
    keyDerivationOptionsObject.value<unsigned int>(
      KeyDerivationOptionsJson::FieldNames::lengthInBytes,
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
    && lengthInBytes != crypto_box_SEEDBYTES
  ) {
    throw InvalidKeyDerivationOptionValueException( (
        "X25519 public key cryptography must use lengthInBytes of " +
        std::to_string(crypto_box_SEEDBYTES)
      ).c_str() );
  }
  if (
    algorithm == KeyDerivationOptionsJson::Algorithm::Ed25519
    && lengthInBytes != crypto_sign_SEEDBYTES
    ) {
    throw InvalidKeyDerivationOptionValueException((
      "Ed25519 signing must use lengthInBytes of " +
      std::to_string(crypto_sign_SEEDBYTES)
      ).c_str());
  }
  if (
    algorithm == KeyDerivationOptionsJson::Algorithm::XSalsa20Poly1305 &&
    lengthInBytes != crypto_stream_xsalsa20_KEYBYTES
  ) {
    throw InvalidKeyDerivationOptionValueException( (
        "XSalsa20Poly1305 symmetric cryptography must use lengthInBytes of " +
        std::to_string(crypto_stream_xsalsa20_KEYBYTES)
      ).c_str() );
  }

	if (type == KeyDerivationOptionsJson::type::Secret) {
		keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::lengthInBytes] = lengthInBytes;
	}

  hashFunction = keyDerivationOptionsObject.value<KeyDerivationOptionsJson::HashFunction>(
      KeyDerivationOptionsJson::FieldNames::hashFunction,
      KeyDerivationOptionsJson::HashFunction::SHA256
  );
  keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunction] = hashFunction;
  hashFunctionMemoryPasses = keyDerivationOptionsObject.value<size_t>(
    KeyDerivationOptionsJson::FieldNames::hashFunctionMemoryPasses,
    (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id || hashFunction == KeyDerivationOptionsJson::HashFunction::Scrypt) ? 2 : 1
  );
  hashFunctionMemoryLimitInBytes = keyDerivationOptionsObject.value<size_t>(
    KeyDerivationOptionsJson::FieldNames::hashFunctionMemoryLimitInBytes, 67108864U
  );
  if (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id || hashFunction == KeyDerivationOptionsJson::HashFunction::Scrypt) {
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunctionMemoryLimitInBytes] = hashFunctionMemoryLimitInBytes;
    keyDerivationOptionsExplicit[KeyDerivationOptionsJson::FieldNames::hashFunctionMemoryPasses] = hashFunctionMemoryPasses;
  }

    if (hashFunction == KeyDerivationOptionsJson::HashFunction::SHA256) {
      hashFunctionImplementation = new HashFunctionSHA256();
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::BLAKE2b) {
      hashFunctionImplementation = new HashFunctionBlake2b();
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::Argon2id) {
      hashFunctionImplementation = new HashFunctionArgon2id(hashFunctionMemoryPasses, hashFunctionMemoryLimitInBytes);
    } else if (hashFunction == KeyDerivationOptionsJson::HashFunction::Scrypt) {
      hashFunctionImplementation = new HashFunctionScrypt(hashFunctionMemoryPasses, hashFunctionMemoryLimitInBytes);
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
  const KeyDerivationOptionsJson::type defaultType
) const {
  const KeyDerivationOptionsJson::type finalType =
    type == KeyDerivationOptionsJson::type::_INVALID_TYPE_ ?
      defaultType : type;
  const std::string typeString =
    finalType == KeyDerivationOptionsJson::type::Secret ? "Secret" :
		finalType == KeyDerivationOptionsJson::type::Symmetric ? "Symmetric" :
		finalType == KeyDerivationOptionsJson::type::Public ? "Public" :
		finalType == KeyDerivationOptionsJson::type::Signing ? "Signing" :
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
    typeString.length() +
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
    typeString.c_str(),
    typeString.length()
  );
  primageWritePtr += typeString.length();
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
        lengthInBytes
    );

  return derivedKey;
}

const SodiumBuffer KeyDerivationOptions::deriveMasterSecret(
		const std::string& seedString,
		const std::string& keyDerivationOptionsJson,
		const KeyDerivationOptionsJson::type typeRequired,
		const size_t lengthInBytesRequired
	) {
    const KeyDerivationOptions keyDerivationOptions(keyDerivationOptionsJson,typeRequired);
    // Ensure that the type in the key derivation options matches the requirement
    if (
      typeRequired != KeyDerivationOptionsJson::type::_INVALID_TYPE_ &&
      typeRequired != keyDerivationOptions.type  
    ) {
      throw InvalidKeyDerivationOptionValueException( (
        "Key generation options must have type " + std::to_string(typeRequired)
      ).c_str() );
    }

    // Verify key-length requirements (if specified)
    if (lengthInBytesRequired > 0 &&
        keyDerivationOptions.lengthInBytes != lengthInBytesRequired) {
      throw InvalidKeyDerivationOptionValueException( (
        "lengthInBytes for this type should be " + std::to_string(lengthInBytesRequired) +
        " but lengthInBytes field was set to " + std::to_string(keyDerivationOptions.lengthInBytes)
        ).c_str()
      );
    }

    return keyDerivationOptions.deriveMasterSecret(seedString, typeRequired);
  }