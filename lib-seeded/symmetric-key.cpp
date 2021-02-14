#include <exception>
#include "symmetric-key.hpp"
#include "packaged-sealed-message.hpp"
#include "recipe.hpp"
#include "exceptions.hpp"
#include "common-names.hpp"

void _crypto_secretbox_nonce_salted(
  unsigned char *nonce,
  const unsigned char *secret_key,
  const unsigned char *message,
  const size_t message_length,
  const char* salt,
  const size_t salt_length
) {
    crypto_generichash_state st;
    crypto_generichash_init(&st, secret_key, crypto_box_SECRETKEYBYTES, crypto_box_NONCEBYTES);
//    crypto_generichash_update(&st, secret_key, crypto_box_SECRETKEYBYTES);
    if (salt_length > 0) {
      crypto_generichash_update(&st, (const unsigned char*) salt, salt_length);
    }
    crypto_generichash_update(&st, message, message_length);
    crypto_generichash_final(&st, nonce, crypto_box_NONCEBYTES);
}

SymmetricKey::SymmetricKey(
  const SodiumBuffer& _keyBytes,
  const std::string _recipe
) : keyBytes(_keyBytes), recipe(_recipe) {
  if (keyBytes.length != crypto_secretbox_KEYBYTES) {
    throw std::invalid_argument("Invalid key length");
  }
}

SymmetricKey::SymmetricKey(
  const SymmetricKey &other
) : SymmetricKey(other.keyBytes, other.recipe) {}

SymmetricKey::SymmetricKey(
  const std::string& seedString,
  const std::string& recipe
) : SymmetricKey(deriveFromSeed(seedString, recipe)) {}

SymmetricKey SymmetricKey::deriveFromSeed(
  const std::string& seedString,
  const std::string& _recipe
) {
  return SymmetricKey(
    Recipe::derivePrimarySecret(
      seedString,
      _recipe,
      RecipeJson::type::SymmetricKey,
      crypto_secretbox_KEYBYTES
    ),
    _recipe
  );
}

const std::vector<unsigned char> SymmetricKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& unsealingInstructions
) const {
  if (messageLength <= 0) {
    throw std::invalid_argument("Invalid message length");
  }
  const size_t ciphertextLength =
    crypto_secretbox_NONCEBYTES + messageLength + crypto_secretbox_MACBYTES;
  std::vector<unsigned char> ciphertext(ciphertextLength);
  unsigned char* noncePtr = ciphertext.data();
  unsigned char* secretBoxStartPtr = noncePtr + crypto_secretbox_NONCEBYTES;

  // Write a nonce derived from the message and symmeetric key
  _crypto_secretbox_nonce_salted(
    noncePtr, keyBytes.data, message, messageLength,
    unsealingInstructions.c_str(), unsealingInstructions.length());
  
  // Create the ciphertext as a secret box
  crypto_secretbox_easy(
    secretBoxStartPtr,
    message,
    messageLength,
    noncePtr,
    keyBytes.data
  );

  return ciphertext;
}

const std::vector<unsigned char> SymmetricKey::sealToCiphertextOnly(
  const SodiumBuffer &message,
  const std::string& unsealingInstructions
) const {
  return sealToCiphertextOnly(message.data, message.length, unsealingInstructions);
}

const PackagedSealedMessage SymmetricKey::seal(
  const SodiumBuffer& message,
  const std::string& unsealingInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message, unsealingInstructions),
    recipe,
    unsealingInstructions
  );
}

  const PackagedSealedMessage SymmetricKey::seal(
    const std::string& message,
    const std::string& unsealingInstructions
  ) const {
    return seal((const unsigned char*)message.c_str(), message.size(), unsealingInstructions);
  }


const PackagedSealedMessage SymmetricKey::seal(
  const std::vector<unsigned char>& message,
  const std::string& unsealingInstructions
) const {
    return PackagedSealedMessage( 
      sealToCiphertextOnly(message.data(), message.size(), unsealingInstructions),
      recipe,
      unsealingInstructions
  );
}


const PackagedSealedMessage SymmetricKey::seal(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& unsealingInstructions
) const {
    return PackagedSealedMessage( 
      sealToCiphertextOnly(message, messageLength, unsealingInstructions),
      recipe,
      unsealingInstructions
  );
}

const SodiumBuffer SymmetricKey::unsealMessageContents(
  const unsigned char* ciphertext,
  const size_t ciphertextLength,
  const std::string& unsealingInstructions
) const {
  if (ciphertextLength <= (crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES)) {
    throw std::invalid_argument("Invalid message length");
  }
  SodiumBuffer plaintextBuffer(ciphertextLength - (crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES));
  const unsigned char* noncePtr = ciphertext;
  const unsigned char* secretBoxStartPtr = noncePtr + crypto_secretbox_NONCEBYTES;

  const int result = crypto_secretbox_open_easy(
    plaintextBuffer.data,
    secretBoxStartPtr,
        ciphertextLength - crypto_secretbox_NONCEBYTES,
    noncePtr,
    keyBytes.data
      );
   if (result != 0) {
     throw CryptographicVerificationFailureException("Symmetric key unseal failed: the key or unsealing instructions must be different from those used to seal the message, or the ciphertext was modified/corrupted.");
   }

  // Recalculate nonce to validate that the provided
  // unsealingInstructions is valid 
  unsigned char recalculatedNonce[crypto_secretbox_NONCEBYTES];
  _crypto_secretbox_nonce_salted(
    recalculatedNonce, keyBytes.data, plaintextBuffer.data, plaintextBuffer.length,
    unsealingInstructions.c_str(), unsealingInstructions.length()
  );
  if (memcmp(recalculatedNonce, noncePtr, crypto_secretbox_NONCEBYTES) != 0) {
     throw CryptographicVerificationFailureException("Symmetric key unseal failed: the key or unsealing instructions must be different from those used to seal the message, or the ciphertext was modified/corrupted.");
  }

  return plaintextBuffer;
}

const SodiumBuffer SymmetricKey::unseal(
  const unsigned char* ciphertext,
  const size_t ciphertextLength,
  const std::string& unsealingInstructions
) const {
  return unsealMessageContents(ciphertext, ciphertextLength, unsealingInstructions);
};

const SodiumBuffer SymmetricKey::unseal(
  const std::vector<unsigned char> &ciphertext,
  const std::string& unsealingInstructions
) const {
  return unseal(ciphertext.data(), ciphertext.size(), unsealingInstructions);
}

const SodiumBuffer SymmetricKey::unseal(
  const PackagedSealedMessage &packagedSealedMessage
) const {
  return unseal(packagedSealedMessage.ciphertext, packagedSealedMessage.unsealingInstructions);
}

/* static */const SodiumBuffer SymmetricKey::unseal(
  const PackagedSealedMessage& packagedSealedMessage,
  const std::string& seedString
) {
  return SymmetricKey::deriveFromSeed(seedString, packagedSealedMessage.recipe)
    .unseal(packagedSealedMessage.ciphertext, packagedSealedMessage.unsealingInstructions);
}


namespace SymmetricKeyJsonField {
  static const std::string keyBytes = "keyBytes";
  static const std::string recipe = CommonNames::recipe;
}

SymmetricKey SymmetricKey::fromJson(
  const std::string& symmetricKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(symmetricKeyAsJson);
    return SymmetricKey(
      SodiumBuffer::fromHexString(jsonObject.at(SymmetricKeyJsonField::keyBytes)),
      jsonObject.value(SymmetricKeyJsonField::recipe, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string SymmetricKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SymmetricKeyJsonField::keyBytes] = keyBytes.toHexString();
  if (recipe.size() > 0) {
    asJson[SymmetricKeyJsonField::recipe] = recipe;
  }
  return asJson.dump(indent, indent_char);
};


const SodiumBuffer SymmetricKey::toSerializedBinaryForm() const {
  SodiumBuffer _recipe = SodiumBuffer(recipe);
  return SodiumBuffer::combineFixedLengthList({
    &keyBytes,
    &_recipe
  });
}

SymmetricKey SymmetricKey::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return SymmetricKey(fields[0], fields[1].toUtf8String());
}
