#include "signing-key.hpp"
#include "recipe.hpp"
#include "sodium-buffer.hpp"
#include "convert.hpp"
#include "exceptions.hpp"
#include "common-names.hpp"
#include "key-formats/OpenSshKey.hpp"
#include "key-formats/OpenPgpKey.hpp"
#include "key-formats/PEM.hpp"

const SodiumBuffer convertSeedToSodiumPrivateKey(const SodiumBuffer& seedOrSodiumPrivateKey) {
  if (seedOrSodiumPrivateKey.length == crypto_sign_SECRETKEYBYTES) {
    return seedOrSodiumPrivateKey;
  } else if (seedOrSodiumPrivateKey.length == crypto_sign_SEEDBYTES) {
    SodiumBuffer sodiumStylePrivateKeyBytes(crypto_sign_SECRETKEYBYTES);
    SodiumBuffer pubBytes(crypto_sign_PUBLICKEYBYTES);
    crypto_sign_seed_keypair(pubBytes.data, sodiumStylePrivateKeyBytes.data, seedOrSodiumPrivateKey.data);
    return sodiumStylePrivateKeyBytes;
  } else {
    throw InvalidRecipeValueException("Invalid signing key size");
  }
}

SigningKey::SigningKey(
  const SodiumBuffer& _signingKeyBytes,
  const std::string& _recipe
) :
  recipe(_recipe),
  signingKeyBytes(convertSeedToSodiumPrivateKey(_signingKeyBytes))
{}

SigningKey::SigningKey(
  const SigningKey& other
) :
  recipe(other.recipe),
  signingKeyBytes(other.signingKeyBytes)
  {}

namespace SigningKeyJsonField {
  static const std::string signingKeyBytes = "signingKeyBytes";
  static const std::string recipe = CommonNames::recipe;
}

SigningKey SigningKey::fromJson(
  const std::string& signingKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(signingKeyAsJson);
    return SigningKey(
      SodiumBuffer::fromHexString(jsonObject.at(SigningKeyJsonField::signingKeyBytes)),
      jsonObject.value(SigningKeyJsonField::recipe, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }

}

SigningKey::SigningKey(
  const std::string& _seedString,
  const std::string& _recipe
) : SigningKey(deriveFromSeed(_seedString, _recipe)) {}


SigningKey SigningKey::deriveFromSeed(
  const std::string& _seedString,
  const std::string& _recipe
) {
  // Turn the seed string into a seed of the appropriate length
  SodiumBuffer seed = Recipe::derivePrimarySecret(
    _seedString,
    _recipe,
    RecipeJson::type::SigningKey,
    crypto_sign_SEEDBYTES
  );
  // Derive a key pair from the seed
  SodiumBuffer signingKeyBytes(crypto_sign_SECRETKEYBYTES);
  std::vector<unsigned char> signatureVerificationKeyBytes(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_seed_keypair(signatureVerificationKeyBytes.data(), signingKeyBytes.data, seed.data);
  return SigningKey(signingKeyBytes, _recipe);
}



const std::vector<unsigned char> SigningKey::getSignatureVerificationKeyBytes() const {
  std::vector<unsigned char> signatureVerificationKeyBytes(crypto_sign_PUBLICKEYBYTES);
  crypto_sign_ed25519_sk_to_pk(signatureVerificationKeyBytes.data(), signingKeyBytes.data);
  return signatureVerificationKeyBytes;
}

const SignatureVerificationKey SigningKey::getSignatureVerificationKey() const {
  return SignatureVerificationKey(getSignatureVerificationKeyBytes(), recipe);
}

const SodiumBuffer SigningKey::getSeedBytes() const {
  SodiumBuffer seed(crypto_sign_SEEDBYTES);
  crypto_sign_ed25519_sk_to_seed(seed.data, signingKeyBytes.data);
  return seed;
}


const std::vector<unsigned char> SigningKey::generateSignature(
  const unsigned char* message,
  const size_t messageLength
) const {
  std::vector<unsigned char> signature(crypto_sign_BYTES);
  unsigned long long siglen_p;
  crypto_sign_detached(signature.data(), &siglen_p, message, messageLength, signingKeyBytes.data);
  return signature;
}

const std::vector<unsigned char> SigningKey::generateSignature(
  const std::vector<unsigned char>& message
) const {
  return generateSignature(message.data(), message.size());
}

const std::string SigningKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SigningKeyJsonField::signingKeyBytes] = signingKeyBytes.toHexString();
  asJson[SigningKeyJsonField::recipe] = recipe;
  return asJson.dump(indent, indent_char);
}

const SodiumBuffer SigningKey::toSerializedBinaryForm() const {
  SodiumBuffer _recipe(recipe);
  return SodiumBuffer::combineFixedLengthList({
    &signingKeyBytes,
    &_recipe
  });
}

SigningKey SigningKey::fromSerializedBinaryForm(
  const SodiumBuffer &serializedBinaryForm
) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return SigningKey(
    fields[0], fields[1].toUtf8String()
  );
}

const std::string SigningKey::toOpenSshPemPrivateKey(const std::string &comment) const {
  return getOpenSshPemPrivateKeyEd25519(*this, comment);
}

const std::string SigningKey::toOpenSshPublicKey() const {
  return getSignatureVerificationKey().toOpenSshPublicKey();
}

const std::string SigningKey::toOpenPgpPemFormatSecretKey(
  const std::string& UserIdPacketContent,
  uint32_t timestamp
) const {
  return generateOpenPgpKey(*this, UserIdPacketContent, timestamp);
}
