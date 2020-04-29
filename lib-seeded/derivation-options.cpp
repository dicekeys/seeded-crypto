#include <cassert>
#include <exception>
#include "sodium.h"
#pragma warning( disable : 26812 )


#include "derivation-options.hpp"
#include "exceptions.hpp"

DerivationOptions::~DerivationOptions() {
  if (hashFunctionImplementation) {
    delete hashFunctionImplementation;
  }
  // if (keyUseRestrictions) {
  //   delete keyUseRestrictions;
  // }
}

// Wrap json parser in a function that throws exceptions as
// InvalidDerivationOptionsJsonException
nlohmann::json parseJsonWithKeyDerviationOptionsExceptions(std::string json) {
  try {
    return nlohmann::json::parse(json);
  } catch (nlohmann::json::exception e) {
    throw InvalidDerivationOptionsJsonException(e.what());
  } catch (...) {
    throw InvalidDerivationOptionsJsonException();
  }
}

// Use the nlohmann::json library to read the JSON-encoded
// key generation options.
// We make heavy use of the library's enum conversion, as documented at:
//   https://github.com/nlohmann/json#specializing-enum-conversion
DerivationOptions::DerivationOptions(
  const std::string& _derivationOptionsJson,
  const DerivationOptionsJson::type typeExpected
) : derivationOptionsJson(_derivationOptionsJson) {
  const nlohmann::json& derivationOptionsObject = parseJsonWithKeyDerviationOptionsExceptions(
    derivationOptionsJson.size() == 0 ? "{}" : derivationOptionsJson
  );

  //
  // type
  //
  type = derivationOptionsObject.value<DerivationOptionsJson::type>(
      DerivationOptionsJson::FieldNames::type,
      typeExpected
    );

  if (typeExpected != DerivationOptionsJson::type::_INVALID_TYPE_ &&
      type != typeExpected) {
    // We were expecting type == typeExpected since typeExpected wasn't invalid,
    // but the JSON specified a different key type
    throw InvalidKeyDerivationOptionValueException("Unexpected type in DerivationOptions");
  }

  if (type == DerivationOptionsJson::type::_INVALID_TYPE_) {
    // No valid type was specified
    throw InvalidKeyDerivationOptionValueException("Invalid type in DerivationOptions");
  }
  derivationOptionsExplicit[DerivationOptionsJson::FieldNames::type] = type;

  //
  // algorithm
  //
  algorithm = derivationOptionsObject.value<DerivationOptionsJson::Algorithm>(
    DerivationOptionsJson::FieldNames::algorithm,
    // Default value depends on the purpose
    (type == DerivationOptionsJson::type::Symmetric) ?
        // For symmetric crypto, default to XSalsa20Poly1305
        DerivationOptionsJson::Algorithm::XSalsa20Poly1305 :
    (type == DerivationOptionsJson::type::Public) ?
      // For public key crypto, default to X25519
      DerivationOptionsJson::Algorithm::X25519 :
    (type == DerivationOptionsJson::type::Signing) ?
      // For public key signing, default to Ed25519
    DerivationOptionsJson::Algorithm::Ed25519 :
      // Otherwise, the leave the key setting to invalid (we don't care about a specific key type)
      DerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_
  );

  // Validate that the key type is allowed for this type
  if (type == DerivationOptionsJson::type::Symmetric &&
      algorithm != DerivationOptionsJson::Algorithm::XSalsa20Poly1305
  ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for symmetric key cryptography"
    );
  }

  if (type == DerivationOptionsJson::type::Public &&
    algorithm != DerivationOptionsJson::Algorithm::X25519
    ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for public key cryptography"
    );
  }
  if (type == DerivationOptionsJson::type::Signing &&
    algorithm != DerivationOptionsJson::Algorithm::Ed25519
    ) {
    throw InvalidKeyDerivationOptionValueException(
      "Invalid algorithm type for signing key"
    );
  }

  if (type != DerivationOptionsJson::type::_INVALID_TYPE_) {
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::type] = type;
  }

  if (algorithm != DerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_) {
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::algorithm] = algorithm;
  }

  //
  // lengthInBytes
  //
  lengthInBytes =
    derivationOptionsObject.value<unsigned int>(
      DerivationOptionsJson::FieldNames::lengthInBytes,
      algorithm == DerivationOptionsJson::Algorithm::X25519 ?
        crypto_box_SEEDBYTES :
      algorithm == DerivationOptionsJson::Algorithm::XSalsa20Poly1305 ?
        // When a 256-bit (32 byte) key is needed, default to 32 bytes
        crypto_stream_xsalsa20_KEYBYTES :
        // When the key type is not defined, default to 32 bytes. 
        32
    );

  if (
    algorithm == DerivationOptionsJson::Algorithm::X25519
    && lengthInBytes != crypto_box_SEEDBYTES
  ) {
    throw InvalidKeyDerivationOptionValueException( (
        "X25519 public key cryptography must use lengthInBytes of " +
        std::to_string(crypto_box_SEEDBYTES)
      ).c_str() );
  }
  if (
    algorithm == DerivationOptionsJson::Algorithm::Ed25519
    && lengthInBytes != crypto_sign_SEEDBYTES
    ) {
    throw InvalidKeyDerivationOptionValueException((
      "Ed25519 signing must use lengthInBytes of " +
      std::to_string(crypto_sign_SEEDBYTES)
      ).c_str());
  }
  if (
    algorithm == DerivationOptionsJson::Algorithm::XSalsa20Poly1305 &&
    lengthInBytes != crypto_stream_xsalsa20_KEYBYTES
  ) {
    throw InvalidKeyDerivationOptionValueException( (
        "XSalsa20Poly1305 symmetric cryptography must use lengthInBytes of " +
        std::to_string(crypto_stream_xsalsa20_KEYBYTES)
      ).c_str() );
  }

	if (type == DerivationOptionsJson::type::Secret) {
		derivationOptionsExplicit[DerivationOptionsJson::FieldNames::lengthInBytes] = lengthInBytes;
	}

  hashFunction = derivationOptionsObject.value<DerivationOptionsJson::HashFunction>(
      DerivationOptionsJson::FieldNames::hashFunction,
      DerivationOptionsJson::HashFunction::SHA256
  );
  derivationOptionsExplicit[DerivationOptionsJson::FieldNames::hashFunction] = hashFunction;
  hashFunctionMemoryPasses = derivationOptionsObject.value<size_t>(
    DerivationOptionsJson::FieldNames::hashFunctionMemoryPasses,
    (hashFunction == DerivationOptionsJson::HashFunction::Argon2id || hashFunction == DerivationOptionsJson::HashFunction::Scrypt) ? 2 : 1
  );
  hashFunctionMemoryLimitInBytes = derivationOptionsObject.value<size_t>(
    DerivationOptionsJson::FieldNames::hashFunctionMemoryLimitInBytes, 67108864U
  );
  if (hashFunction == DerivationOptionsJson::HashFunction::Argon2id || hashFunction == DerivationOptionsJson::HashFunction::Scrypt) {
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::hashFunctionMemoryLimitInBytes] = hashFunctionMemoryLimitInBytes;
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::hashFunctionMemoryPasses] = hashFunctionMemoryPasses;
  }

    if (hashFunction == DerivationOptionsJson::HashFunction::SHA256) {
      hashFunctionImplementation = new HashFunctionSHA256();
    } else if (hashFunction == DerivationOptionsJson::HashFunction::BLAKE2b) {
      hashFunctionImplementation = new HashFunctionBlake2b();
    } else if (hashFunction == DerivationOptionsJson::HashFunction::Argon2id) {
      hashFunctionImplementation = new HashFunctionArgon2id(hashFunctionMemoryPasses, hashFunctionMemoryLimitInBytes);
    } else if (hashFunction == DerivationOptionsJson::HashFunction::Scrypt) {
      hashFunctionImplementation = new HashFunctionScrypt(hashFunctionMemoryPasses, hashFunctionMemoryLimitInBytes);
    } else {
      throw std::invalid_argument("Invalid hashFunction");
    }
}


const std::string DerivationOptions::derivationOptionsJsonWithAllOptionalParametersSpecified(
  int indent,
  const char indent_char
) const {
  return derivationOptionsExplicit.dump(indent, indent_char);
}


const SodiumBuffer DerivationOptions::deriveMasterSecret(
  const std::string& seedString,
  const DerivationOptionsJson::type defaultType
) const {
  const DerivationOptionsJson::type finalType =
    type == DerivationOptionsJson::type::_INVALID_TYPE_ ?
      defaultType : type;
  const std::string typeString =
    finalType == DerivationOptionsJson::type::Secret ? "Secret" :
		finalType == DerivationOptionsJson::type::Symmetric ? "Symmetric" :
		finalType == DerivationOptionsJson::type::Public ? "Public" :
		finalType == DerivationOptionsJson::type::Signing ? "Signing" :
    "";

  // Create a hash preimage that is the seed string, followed by a null
  // terminator, followed by the derivationOptionsJson string.
  //   <seedString> + '\0' <derivationOptionsJson>
  SodiumBuffer preimage(
    // length of the seed string
    seedString.length() +
    // 1 character for a null char between the two strings
    1 +
    // length of key type
    typeString.length() +
    // length of the json string specifying the derivation options
    derivationOptionsJson.length()
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
    derivationOptionsJson.c_str(),
    derivationOptionsJson.length()
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

const SodiumBuffer DerivationOptions::deriveMasterSecret(
		const std::string& seedString,
		const std::string& derivationOptionsJson,
		const DerivationOptionsJson::type typeRequired,
		const size_t lengthInBytesRequired
	) {
    const DerivationOptions DerivationOptions(derivationOptionsJson,typeRequired);
    // Ensure that the type in the key derivation options matches the requirement
    if (
      typeRequired != DerivationOptionsJson::type::_INVALID_TYPE_ &&
      typeRequired != DerivationOptions.type  
    ) {
      throw InvalidKeyDerivationOptionValueException( (
        "Key generation options must have type " + std::to_string(typeRequired)
      ).c_str() );
    }

    // Verify key-length requirements (if specified)
    if (lengthInBytesRequired > 0 &&
        DerivationOptions.lengthInBytes != lengthInBytesRequired) {
      throw InvalidKeyDerivationOptionValueException( (
        "lengthInBytes for this type should be " + std::to_string(lengthInBytesRequired) +
        " but lengthInBytes field was set to " + std::to_string(DerivationOptions.lengthInBytes)
        ).c_str()
      );
    }

    return DerivationOptions.deriveMasterSecret(seedString, typeRequired);
  }