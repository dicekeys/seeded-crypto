// #include <cassert>
#include <exception>
#include "sodium.h"
#include "hkdf.hpp"

#pragma warning( disable : 26812 )

#include "derivation-options.hpp"
#include "exceptions.hpp"
#include "word-lists.hpp"

extern "C" {
#include "../extern/libsodium/src/libsodium/crypto_pwhash/argon2/argon2.h"
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
  const DerivationOptionsJson::type typeRequired
) : derivationOptionsJson(_derivationOptionsJson) {
  const nlohmann::json& derivationOptionsObject = parseJsonWithKeyDerviationOptionsExceptions(
    derivationOptionsJson.size() == 0 ? "{}" : derivationOptionsJson
  );
  this->wordList = DerivationOptionsJson::WordList::_INVALID_WORD_LIST_;

  //
  // type
  //
  type = derivationOptionsObject.value<DerivationOptionsJson::type>(
      DerivationOptionsJson::FieldNames::type,
      typeRequired
    );

  if (typeRequired != DerivationOptionsJson::type::_INVALID_TYPE_ &&
      type != typeRequired) {
    // We required type == typeRequired since typeRequired wasn't invalid,
    // but the JSON specified a different key type
    throw InvalidDerivationOptionValueException("Unexpected type in DerivationOptions");
  }

  if (type != DerivationOptionsJson::type::_INVALID_TYPE_) {
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::type] = type;
  }

  //
  // algorithm
  //
  algorithm = derivationOptionsObject.value<DerivationOptionsJson::Algorithm>(
    DerivationOptionsJson::FieldNames::algorithm,
    // Default value depends on the purpose
    (type == DerivationOptionsJson::type::SymmetricKey) ?
        // For symmetric crypto, default to XSalsa20Poly1305
        DerivationOptionsJson::Algorithm::XSalsa20Poly1305 :
    (type == DerivationOptionsJson::type::UnsealingKey) ?
      // For public key crypto, default to X25519
      DerivationOptionsJson::Algorithm::X25519 :
    (type == DerivationOptionsJson::type::SigningKey) ?
      // For public key signing, default to Ed25519
    DerivationOptionsJson::Algorithm::Ed25519 :
      // Otherwise, the leave the key setting to invalid (we don't care about a specific key type)
      DerivationOptionsJson::Algorithm::_INVALID_ALGORITHM_
  );

  // Validate that the key type is allowed for this type
  if (type == DerivationOptionsJson::type::SymmetricKey &&
      algorithm != DerivationOptionsJson::Algorithm::XSalsa20Poly1305
  ) {
    throw InvalidDerivationOptionValueException(
      "Invalid algorithm type for symmetric key cryptography"
    );
  }

  if (type == DerivationOptionsJson::type::UnsealingKey &&
    algorithm != DerivationOptionsJson::Algorithm::X25519
    ) {
    throw InvalidDerivationOptionValueException(
      "Invalid algorithm type for public key cryptography"
    );
  }
  if (type == DerivationOptionsJson::type::SigningKey &&
    algorithm != DerivationOptionsJson::Algorithm::Ed25519
    ) {
    throw InvalidDerivationOptionValueException(
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

  if (type == DerivationOptionsJson::type::Password) {
    // Determine the word list used to generate a password
    wordList = derivationOptionsObject.value<DerivationOptionsJson::WordList>(
      DerivationOptionsJson::FieldNames::wordList, DerivationOptionsJson::WordList::EN_512_words_5_chars_max_ed_4_20200917
    );
    // Determine the bitsPerWord from the password;
    double bitsPerWord = log2(getWordList(wordList).size());

    // For password derivations, a length may be specified in bits of entropy
    // or in words.
    lengthInBits = derivationOptionsObject.value<unsigned int>(
        DerivationOptionsJson::FieldNames::lengthInBits, 0
    );
    lengthInWords = derivationOptionsObject.value<unsigned int>(
      DerivationOptionsJson::FieldNames::lengthInWords, 0
    );
    // If no length specified, derive a password with 128-bits of entropy
    // (if it's good enough for an AES block, it's good enough for a password).
    if (lengthInBits > 0 && lengthInWords > 0 && lengthInWords != (unsigned int)ceil(lengthInBits * bitsPerWord)) {
      throw InvalidDerivationOptionValueException( 
        "lengthInBits and lengthInWords conflict"
      );
    } else if (lengthInBits == 0) {
      if (lengthInWords == 0) {
        lengthInBits = 128;
      } else {
        // If the length is specified in words, derive the lengthInBits
        lengthInBits = (unsigned int)floor( ((double)lengthInWords) * bitsPerWord);
      }
    }
    if (lengthInWords == 0 && lengthInBits > 0) {
      // If the length is specified in bits, derive the number of words
      // we'll need by taking the ceiling of the length in bits / bits per word
      lengthInWords = (unsigned int)ceil( ((double)lengthInBits) / bitsPerWord );
    }
    // The length in bytes should be the ceiling of the bits needed for all the words.
    lengthInBytes = lengthInWords * BytesPerWordOfPassword;
  }


  if (
    algorithm == DerivationOptionsJson::Algorithm::X25519
    && lengthInBytes != crypto_box_SEEDBYTES
  ) {
    throw InvalidDerivationOptionValueException( (
        "X25519 public key cryptography must use lengthInBytes of " +
        std::to_string(crypto_box_SEEDBYTES)
      ).c_str() );
  }
  if (
    algorithm == DerivationOptionsJson::Algorithm::Ed25519
    && lengthInBytes != crypto_sign_SEEDBYTES
    ) {
    throw InvalidDerivationOptionValueException((
      "Ed25519 signing must use lengthInBytes of " +
      std::to_string(crypto_sign_SEEDBYTES)
      ).c_str());
  }
  if (
    algorithm == DerivationOptionsJson::Algorithm::XSalsa20Poly1305 &&
    lengthInBytes != crypto_stream_xsalsa20_KEYBYTES
  ) {
    throw InvalidDerivationOptionValueException( (
        "XSalsa20Poly1305 symmetric cryptography must use lengthInBytes of " +
        std::to_string(crypto_stream_xsalsa20_KEYBYTES)
      ).c_str() );
  }

	if (type == DerivationOptionsJson::type::Secret) {
		derivationOptionsExplicit[DerivationOptionsJson::FieldNames::lengthInBytes] = lengthInBytes;
	}

  hashFunction = derivationOptionsObject.value<DerivationOptionsJson::HashFunction>(
      DerivationOptionsJson::FieldNames::hashFunction,
      DerivationOptionsJson::HashFunction::BLAKE2b
  );
  if (hashFunction != DerivationOptionsJson::HashFunction::BLAKE2b && hashFunction != DerivationOptionsJson::HashFunction::Argon2id) {
    throw std::invalid_argument("Invalid hashFunction");
  }
  derivationOptionsExplicit[DerivationOptionsJson::FieldNames::hashFunction] = hashFunction;
  hashFunctionMemoryPasses = derivationOptionsObject.value<size_t>(
    DerivationOptionsJson::FieldNames::hashFunctionMemoryPasses,
    (hashFunction == DerivationOptionsJson::HashFunction::Argon2id) ? 2 : 1
  );
  hashFunctionMemoryLimitInBytes = derivationOptionsObject.value<size_t>(
    DerivationOptionsJson::FieldNames::hashFunctionMemoryLimitInBytes, 67108864U
  );
  if (hashFunction == DerivationOptionsJson::HashFunction::Argon2id) {
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::hashFunctionMemoryLimitInBytes] = hashFunctionMemoryLimitInBytes;
    derivationOptionsExplicit[DerivationOptionsJson::FieldNames::hashFunctionMemoryPasses] = hashFunctionMemoryPasses;
  }

}


const std::string DerivationOptions::derivationOptionsJsonWithAllOptionalParametersSpecified(
  int indent,
  const char indent_char
) const {
  return derivationOptionsExplicit.dump(indent, indent_char);
}


const SodiumBuffer DerivationOptions::derivePrimarySecret(
  const std::string& seedString,
  const DerivationOptionsJson::type defaultType
) const {
  const DerivationOptionsJson::type finalType =
    type == DerivationOptionsJson::type::_INVALID_TYPE_ ?
      defaultType : type;
  const std::string typeString =
     finalType == DerivationOptionsJson::type::Password ? "Password" :
     finalType == DerivationOptionsJson::type::Secret ? "Secret" :
		 finalType == DerivationOptionsJson::type::SymmetricKey ? "SymmetricKey" :
		 finalType == DerivationOptionsJson::type::UnsealingKey ? "UnsealingKey" :
		 finalType == DerivationOptionsJson::type::SigningKey ? "SigningKey" :
     "";

  // Create a hash preimage that is the seed string, followed by a null
  // terminator, followed by the derivationOptionsJson string.
  //   <seedString> + '\0' <derivationOptionsJson>
  SodiumBuffer keyTypeAndDerivationOptions(
    // length of key type
    typeString.length() +
    // length of the json string specifying the derivation options
    derivationOptionsJson.length()
  );

  // Use this moving pointer to write the primage
  unsigned char* writePtr = keyTypeAndDerivationOptions.data;
  // copy the key type
  memcpy(
    writePtr,
    typeString.c_str(),
    typeString.length()
  );
  writePtr += typeString.length();
  // copy the key derivation options into the preimage
  memcpy(
    writePtr,
    derivationOptionsJson.c_str(),
    derivationOptionsJson.length()
  );



  if (this->hashFunction == DerivationOptionsJson::HashFunction::Argon2id) {
    if (this->lengthInBytes > crypto_pwhash_argon2id_BYTES_MAX ) {
      throw std::invalid_argument("Invalid hash length");
    }
    SodiumBuffer hashOutput(std::max(crypto_pwhash_argon2id_BYTES_MIN, this->lengthInBytes));
    const int hashSuccessOutcome = argon2id_hash_raw(
      // opsLimit
      (uint32_t) this->hashFunctionMemoryPasses,
      // memLimit
      (uint32_t) (this->hashFunctionMemoryLimitInBytes / 1024U),
      // parallelism (same as default for libSodium: 1
      (uint32_t) 1U,
      // The password pointer/length are where we submit the seed and its length
      seedString.c_str(), seedString.length(),
      // We salt with the keyTypeAndDerivationOptions
      keyTypeAndDerivationOptions.data, keyTypeAndDerivationOptions.length,
      // The output goes into result
      hashOutput.data, hashOutput.length
    );
    if (hashSuccessOutcome != ARGON2_OK) {
      throw std::bad_alloc();
    }
    if (hashOutput.length > this->lengthInBytes) {
      SodiumBuffer trimmedHashOutput(this->lengthInBytes);
      memcpy(trimmedHashOutput.data, hashOutput.data, trimmedHashOutput.length);
      return trimmedHashOutput;
    } else {
      return hashOutput;
    }
  } else {
    // Blake2b
    return hkdfBlake2b((unsigned char*) seedString.c_str(), seedString.length(), keyTypeAndDerivationOptions, this->lengthInBytes);
  }
}

const SodiumBuffer DerivationOptions::derivePrimarySecret(
		const std::string& seedString,
		const std::string& derivationOptionsJson,
		const DerivationOptionsJson::type typeRequired,
		const size_t lengthInBytesRequired
	) {
    const DerivationOptions derivationOptions(derivationOptionsJson,typeRequired);

    // Verify key-length requirements (if specified)
    if (lengthInBytesRequired > 0 &&
        derivationOptions.lengthInBytes != lengthInBytesRequired) {
      throw InvalidDerivationOptionValueException( (
        "lengthInBytes for this type should be " + std::to_string(lengthInBytesRequired) +
        " but lengthInBytes field was set to " + std::to_string(derivationOptions.lengthInBytes)
        ).c_str()
      );
    }

    return derivationOptions.derivePrimarySecret(seedString, typeRequired);
  }