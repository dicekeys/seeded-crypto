#include "github-com-nlohmann-json/json.hpp"
#include "public-key.hpp"
#include "crypto_box_seal_salted.h"
#include "convert.hpp"
#include "lib-seeded.hpp"

namespace PublicKeyJsonFieldName {
  const std::string keyBytes = "keyBytes";
  const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

PublicKey::PublicKey(
    const std::vector<unsigned char> &publicKeyBytes,
    const std::string &keyDerivationOptionsJson
  ) : publicKeyBytes(publicKeyBytes), keyDerivationOptionsJson(keyDerivationOptionsJson) {
    if (publicKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw std::invalid_argument("Invalid key size exception");
    }
  }

PublicKey constructPublicKeyFromJson(const std::string &publicKeyAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(publicKeyAsJson);
    return PublicKey(
      hexStrToByteVector(jsonObject.value<std::string>(PublicKeyJsonFieldName::keyBytes, "")),
      jsonObject.value<std::string>(PublicKeyJsonFieldName::keyDerivationOptionsJson, "")
    );
  } catch (std::exception e) {
    throw JsonParsingException(e.what());
  }
}

PublicKey::PublicKey(const std::string &publicKeyAsJson) :
  PublicKey(constructPublicKeyFromJson(publicKeyAsJson)) {}


const std::string PublicKey::toJson(
  int indent,
  const char indent_char
) const {
	nlohmann::json asJson;  
  asJson[PublicKeyJsonFieldName::keyBytes] =
    getkeyBytes();
  asJson[PublicKeyJsonFieldName::keyDerivationOptionsJson] =
    keyDerivationOptionsJson;
  return asJson.dump(indent, indent_char);
};


const std::vector<unsigned char> PublicKey::seal(
  const unsigned char* message,
  const size_t messageLength,
  const std::vector<unsigned char> &publicKey,
  const std::string &postDecryptionInstructionsJson
) {
  if (publicKey.size() != crypto_box_PUBLICKEYBYTES) {
    throw std::invalid_argument("Invalid key size");
  }
  if (messageLength <= 0) {
    throw std::invalid_argument("Invalid message length");
  }
  const size_t ciphertextLength =
    messageLength + crypto_box_SEALBYTES;
  std::vector<unsigned char> ciphertext(ciphertextLength);

  crypto_box_salted_seal(
    ciphertext.data(),
    message,
    messageLength,
    publicKey.data(),
    postDecryptionInstructionsJson.c_str(),
    postDecryptionInstructionsJson.length()
  );

  return ciphertext;
}

const std::vector<unsigned char> PublicKey::seal(
  const SodiumBuffer &message,
  const std::vector<unsigned char> &publicKey,
  const std::string &postDecryptionInstructionsJson
) {
  return PublicKey::seal(
    message.data, message.length, publicKey, postDecryptionInstructionsJson
  );
}

const std::vector<unsigned char> PublicKey::seal(
  const unsigned char* message,
  const size_t messageLength,
  const std::string &postDecryptionInstructionsJson
) const {
  return PublicKey::seal(message, messageLength, publicKeyBytes, postDecryptionInstructionsJson);
}

const std::vector<unsigned char> PublicKey::seal(
  const SodiumBuffer& message,
  const std::string &postDecryptionInstructionsJson
) const {
  return seal(message.data, message.length, postDecryptionInstructionsJson);
}



const std::vector<unsigned char> PublicKey::getPublicKeyBytes(
) const {
  return publicKeyBytes;
}

const std::string PublicKey::getkeyBytes(
) const {
  return toHexStr(publicKeyBytes);
}
