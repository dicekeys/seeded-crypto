// #include <cassert>
#include <exception>
#include <string>
#include "sodium.h"
#include "hkdf.hpp"

#pragma warning( disable : 26812 )

#include "recipe.hpp"
#include "exceptions.hpp"
#include "word-lists.hpp"

extern "C" {
#include "../extern/libsodium/src/libsodium/crypto_pwhash/argon2/argon2.h"
}

// Wrap json parser in a function that throws exceptions as
// InvalidRecipeJsonException
nlohmann::json parseJsonWithKeyDerviationOptionsExceptions(std::string json) {
  try {
    return nlohmann::json::parse(json);
  } catch (nlohmann::json::exception e) {
    throw InvalidRecipeJsonException(e.what());
  } catch (...) {
    throw InvalidRecipeJsonException();
  }
}


// Use the nlohmann::json library to read the JSON-encoded
// key generation options.
// We make heavy use of the library's enum conversion, as documented at:
//   https://github.com/nlohmann/json#specializing-enum-conversion
Recipe::Recipe(
  const std::string& _recipe,
  const RecipeJson::type typeRequired
) : recipe(_recipe) {
  const nlohmann::json& recipeObject = parseJsonWithKeyDerviationOptionsExceptions(
    recipe.size() == 0 ? "{}" : recipe
  );
  this->wordList = RecipeJson::WordList::_INVALID_WORD_LIST_;

  //
  // type
  //
  type = recipeObject.value<RecipeJson::type>(
      RecipeJson::FieldNames::type,
      typeRequired
    );

  if (typeRequired != RecipeJson::type::_INVALID_TYPE_ &&
      type != typeRequired) {
    // We required type == typeRequired since typeRequired wasn't invalid,
    // but the JSON specified a different key type
    throw InvalidDerivationOptionValueException("Unexpected type in Recipe");
  }

  if (type != RecipeJson::type::_INVALID_TYPE_) {
    recipeExplicit[RecipeJson::FieldNames::type] = type;
  }

  //
  // algorithm
  //
  algorithm = recipeObject.value<RecipeJson::Algorithm>(
    RecipeJson::FieldNames::algorithm,
    // Default value depends on the purpose
    (type == RecipeJson::type::SymmetricKey) ?
        // For symmetric crypto, default to XSalsa20Poly1305
        RecipeJson::Algorithm::XSalsa20Poly1305 :
    (type == RecipeJson::type::UnsealingKey) ?
      // For public key crypto, default to X25519
      RecipeJson::Algorithm::X25519 :
    (type == RecipeJson::type::SigningKey) ?
      // For public key signing, default to Ed25519
    RecipeJson::Algorithm::Ed25519 :
      // Otherwise, the leave the key setting to invalid (we don't care about a specific key type)
      RecipeJson::Algorithm::_INVALID_ALGORITHM_
  );

  // Validate that the key type is allowed for this type
  if (type == RecipeJson::type::SymmetricKey &&
      algorithm != RecipeJson::Algorithm::XSalsa20Poly1305
  ) {
    throw InvalidDerivationOptionValueException(
      "Invalid algorithm type for symmetric key cryptography"
    );
  }

  if (type == RecipeJson::type::UnsealingKey &&
    algorithm != RecipeJson::Algorithm::X25519
    ) {
    throw InvalidDerivationOptionValueException(
      "Invalid algorithm type for public key cryptography"
    );
  }
  if (type == RecipeJson::type::SigningKey &&
    algorithm != RecipeJson::Algorithm::Ed25519
    ) {
    throw InvalidDerivationOptionValueException(
      "Invalid algorithm type for signing key"
    );
  }

  if (type != RecipeJson::type::_INVALID_TYPE_) {
    recipeExplicit[RecipeJson::FieldNames::type] = type;
  }

  if (algorithm != RecipeJson::Algorithm::_INVALID_ALGORITHM_) {
    recipeExplicit[RecipeJson::FieldNames::algorithm] = algorithm;
  }

  //
  // lengthInBytes
  //
  lengthInBytes =
    recipeObject.value<unsigned int>(
      RecipeJson::FieldNames::lengthInBytes,
      algorithm == RecipeJson::Algorithm::X25519 ?
        crypto_box_SEEDBYTES :
      algorithm == RecipeJson::Algorithm::XSalsa20Poly1305 ?
        // When a 256-bit (32 byte) key is needed, default to 32 bytes
        crypto_stream_xsalsa20_KEYBYTES :
        // When the key type is not defined, default to 32 bytes. 
        32
    );

  if (type == RecipeJson::type::Password) {
    // Determine the word list used to generate a password
    wordList = recipeObject.value<RecipeJson::WordList>(
      RecipeJson::FieldNames::wordList, RecipeJson::WordList::EN_512_words_5_chars_max_ed_4_20200917
    );
    // Determine the bitsPerWord from the password;
    double bitsPerWord = log2(getWordList(wordList).size());

    // For password derivations, a length may be specified in bits of entropy
    // or in words.
    lengthInBits = recipeObject.value<unsigned int>(
        RecipeJson::FieldNames::lengthInBits, 0
    );
    lengthInWords = recipeObject.value<unsigned int>(
      RecipeJson::FieldNames::lengthInWords, 0
    );
    lengthInChars = recipeObject.value<size_t>(
      RecipeJson::FieldNames::lengthInChars, std::string::npos
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
    algorithm == RecipeJson::Algorithm::X25519
    && lengthInBytes != crypto_box_SEEDBYTES
  ) {
    throw InvalidDerivationOptionValueException( (
        "X25519 public key cryptography must use lengthInBytes of " +
        std::to_string(crypto_box_SEEDBYTES)
      ).c_str() );
  }
  if (
    algorithm == RecipeJson::Algorithm::Ed25519
    && lengthInBytes != crypto_sign_SEEDBYTES
    ) {
    throw InvalidDerivationOptionValueException((
      "Ed25519 signing must use lengthInBytes of " +
      std::to_string(crypto_sign_SEEDBYTES)
      ).c_str());
  }
  if (
    algorithm == RecipeJson::Algorithm::XSalsa20Poly1305 &&
    lengthInBytes != crypto_stream_xsalsa20_KEYBYTES
  ) {
    throw InvalidDerivationOptionValueException( (
        "XSalsa20Poly1305 symmetric cryptography must use lengthInBytes of " +
        std::to_string(crypto_stream_xsalsa20_KEYBYTES)
      ).c_str() );
  }

	if (type == RecipeJson::type::Secret) {
		recipeExplicit[RecipeJson::FieldNames::lengthInBytes] = lengthInBytes;
	}

  hashFunction = recipeObject.value<RecipeJson::HashFunction>(
      RecipeJson::FieldNames::hashFunction,
      RecipeJson::HashFunction::BLAKE2b
  );
  if (hashFunction != RecipeJson::HashFunction::BLAKE2b && hashFunction != RecipeJson::HashFunction::Argon2id) {
    throw std::invalid_argument("Invalid hashFunction");
  }
  recipeExplicit[RecipeJson::FieldNames::hashFunction] = hashFunction;
  hashFunctionMemoryPasses = recipeObject.value<size_t>(
    RecipeJson::FieldNames::hashFunctionMemoryPasses,
    (hashFunction == RecipeJson::HashFunction::Argon2id) ? 2 : 1
  );
  hashFunctionMemoryLimitInBytes = recipeObject.value<size_t>(
    RecipeJson::FieldNames::hashFunctionMemoryLimitInBytes, 67108864U
  );
  if (hashFunction == RecipeJson::HashFunction::Argon2id) {
    recipeExplicit[RecipeJson::FieldNames::hashFunctionMemoryLimitInBytes] = hashFunctionMemoryLimitInBytes;
    recipeExplicit[RecipeJson::FieldNames::hashFunctionMemoryPasses] = hashFunctionMemoryPasses;
  }

}


const std::string Recipe::recipeWithAllOptionalParametersSpecified(
  int indent,
  const char indent_char
) const {
  return recipeExplicit.dump(indent, indent_char);
}


const SodiumBuffer Recipe::derivePrimarySecret(
  const std::string& seedString,
  const RecipeJson::type defaultType
) const {
  const RecipeJson::type finalType =
    type == RecipeJson::type::_INVALID_TYPE_ ?
      defaultType : type;
  const std::string typeString =
     finalType == RecipeJson::type::Password ? "Password" :
     finalType == RecipeJson::type::Secret ? "Secret" :
		 finalType == RecipeJson::type::SymmetricKey ? "SymmetricKey" :
		 finalType == RecipeJson::type::UnsealingKey ? "UnsealingKey" :
		 finalType == RecipeJson::type::SigningKey ? "SigningKey" :
     "";

  // Create a hash preimage that is the seed string, followed by a null
  // terminator, followed by the recipe string.
  //   <seedString> + '\0' <recipe>
  SodiumBuffer keyTypeAndRecipe(
    // length of key type
    typeString.length() +
    // length of the json string specifying the recipe
    recipe.length()
  );

  // Use this moving pointer to write the primage
  unsigned char* writePtr = keyTypeAndRecipe.data;
  // copy the key type
  memcpy(
    writePtr,
    typeString.c_str(),
    typeString.length()
  );
  writePtr += typeString.length();
  // copy the key recipe into the preimage
  memcpy(
    writePtr,
    recipe.c_str(),
    recipe.length()
  );



  if (this->hashFunction == RecipeJson::HashFunction::Argon2id) {
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
      // We salt with the keyTypeAndRecipe
      keyTypeAndRecipe.data, keyTypeAndRecipe.length,
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
    return hkdfBlake2b((unsigned char*) seedString.c_str(), seedString.length(), keyTypeAndRecipe, this->lengthInBytes);
  }
}

const SodiumBuffer Recipe::derivePrimarySecret(
		const std::string& seedString,
		const std::string& recipe,
		const RecipeJson::type typeRequired,
		const size_t lengthInBytesRequired
	) {
    const Recipe recipeObj(recipe,typeRequired);

    // Verify key-length requirements (if specified)
    if (lengthInBytesRequired > 0 &&
        recipeObj.lengthInBytes != lengthInBytesRequired) {
      throw InvalidDerivationOptionValueException( (
        "lengthInBytes for this type should be " + std::to_string(lengthInBytesRequired) +
        " but lengthInBytes field was set to " + std::to_string(recipeObj.lengthInBytes)
        ).c_str()
      );
    }

    return recipeObj.derivePrimarySecret(seedString, typeRequired);
  }