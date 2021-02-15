#include "github-com-nlohmann-json/json.hpp"
#include "unsealing-key.hpp"
#include "crypto_box_seal_salted.h"
#include "recipe.hpp"
#include "convert.hpp"
#include "exceptions.hpp"
#include "common-names.hpp"

UnsealingKey::UnsealingKey(
    const SodiumBuffer _unsealingKeyBytes,
    const std::vector<unsigned char> _sealingKeyBytes,
    const std::string _recipe
  ) :
    unsealingKeyBytes(_unsealingKeyBytes),
    sealingKeyBytes(_sealingKeyBytes),
    recipe(_recipe)
    {
    if (sealingKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw InvalidRecipeValueException("Invalid public key size");
    }
    if (unsealingKeyBytes.length != crypto_box_SECRETKEYBYTES) {
      throw InvalidRecipeValueException("Invalid private key size for public/private key pair");
    }
  }

UnsealingKey::UnsealingKey(
  const SodiumBuffer &seedBuffer,
  const std::string& _recipe
) : recipe(_recipe), sealingKeyBytes(crypto_box_PUBLICKEYBYTES), unsealingKeyBytes(crypto_box_SECRETKEYBYTES) {
  if (seedBuffer.length < crypto_box_SEEDBYTES){
    throw std::invalid_argument("Insufficient seed length");
  }
  crypto_box_seed_keypair((unsigned char *) sealingKeyBytes.data(), unsealingKeyBytes.data, seedBuffer.data);
}

UnsealingKey::UnsealingKey(
  const std::string& _seedString,
  const std::string& _recipe
) : UnsealingKey(deriveFromSeed(_seedString, _recipe)) {}

UnsealingKey UnsealingKey::deriveFromSeed(
  const std::string& seedString,
  const std::string& recipe
) {
  return UnsealingKey(
    Recipe::derivePrimarySecret(seedString, recipe, RecipeJson::type::UnsealingKey, crypto_box_SEEDBYTES),
    recipe
  );
}


UnsealingKey::UnsealingKey(
  const UnsealingKey &other
):
  sealingKeyBytes(other.sealingKeyBytes), 
  recipe(other.recipe),
  unsealingKeyBytes(other.unsealingKeyBytes)
  {}

const SodiumBuffer UnsealingKey::unseal(
  const unsigned char* ciphertext,
  const size_t ciphertextLength,
  const std::string& unsealingInstructions
) const {
  if (ciphertextLength <= crypto_box_SEALBYTES) {
    throw CryptographicVerificationFailureException("Public/Private unseal failed: Invalid message length");
  }
  SodiumBuffer plaintext(ciphertextLength -crypto_box_SEALBYTES);

  const int result = crypto_box_salted_seal_open(
    plaintext.data,
    ciphertext,
    ciphertextLength,
    sealingKeyBytes.data(),
    unsealingKeyBytes.data,
    unsealingInstructions.c_str(),
    unsealingInstructions.length()
  );
  if (result != 0) {
    throw CryptographicVerificationFailureException("Public/Private unseal failed: the private key doesn't match the public key used to seal the message, the unsealing instructions do not match those used to seal the message, or the ciphertext was modified/corrupted.");
  }
  return plaintext;
}

const SodiumBuffer UnsealingKey::unseal(
  const std::vector<unsigned char> &ciphertext,
  const std::string& unsealingInstructions
) const {
  return unseal(ciphertext.data(), ciphertext.size(), unsealingInstructions
  );
};

const SodiumBuffer UnsealingKey::unseal(
  const PackagedSealedMessage &packagedSealedMessage
) const {
  return unseal(packagedSealedMessage.ciphertext, packagedSealedMessage.unsealingInstructions);
}

const SealingKey UnsealingKey::getSealingKey() const {
  return SealingKey(sealingKeyBytes, recipe);
}


/////
//  JSON
////
namespace UnsealingKeyJsonField {
  static const std::string sealingKeyBytes = "sealingKeyBytes";
  static const std::string unsealingKeyBytes = "unsealingKeyBytes";
  static const std::string recipe = CommonNames::recipe;
}

UnsealingKey UnsealingKey::fromJson(
  const std::string& unsealingKeyAsJson
) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(unsealingKeyAsJson);
    return UnsealingKey(
      SodiumBuffer::fromHexString(jsonObject.at(UnsealingKeyJsonField::unsealingKeyBytes)),
      hexStrToByteVector(jsonObject.at(UnsealingKeyJsonField::sealingKeyBytes)),
      jsonObject.value(UnsealingKeyJsonField::recipe, ""));
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string UnsealingKey::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[UnsealingKeyJsonField::unsealingKeyBytes] = unsealingKeyBytes.toHexString();
  asJson[UnsealingKeyJsonField::sealingKeyBytes] = toHexStr(sealingKeyBytes);
  asJson[UnsealingKeyJsonField::recipe] = recipe;
  return asJson.dump(indent, indent_char);
};


const SodiumBuffer UnsealingKey::toSerializedBinaryForm() const {
  SodiumBuffer recipeBuffer = SodiumBuffer(recipe);
  SodiumBuffer _SealingKeyBytes(sealingKeyBytes);
  SodiumBuffer _recipe(recipe);
  return SodiumBuffer::combineFixedLengthList({
    &unsealingKeyBytes,
    &_SealingKeyBytes,
    &_recipe
  });
}

UnsealingKey UnsealingKey::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(3);
  return UnsealingKey(fields[0], fields[1].toVector(), fields[2].toUtf8String());
}
