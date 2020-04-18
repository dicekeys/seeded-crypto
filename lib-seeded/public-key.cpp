#include "github-com-nlohmann-json/json.hpp"
#include "public-key.hpp"
#include "crypto_box_seal_salted.h"
#include "convert.hpp"
#include "lib-seeded.hpp"
#include "exceptions.hpp"

namespace PublicKeyJsonFieldName {
  const std::string keyBytes = "keyBytes";
  const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

PublicKey::PublicKey(
    const std::vector<unsigned char> &_publicKeyBytes,
    const std::string& _keyDerivationOptionsJson
  ) : publicKeyBytes(_publicKeyBytes), keyDerivationOptionsJson(_keyDerivationOptionsJson) {
    if (publicKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw InvalidKeyDerivationOptionValueException("Invalid key size exception");
    }
  }

PublicKey PublicKey::fromJson(const std::string& publicKeyAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(publicKeyAsJson);
    return PublicKey(
      hexStrToByteVector(jsonObject.at(PublicKeyJsonFieldName::keyBytes)),
      jsonObject.value(PublicKeyJsonFieldName::keyDerivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string PublicKey::toJson(
  int indent,
  const char indent_char
) const {
	nlohmann::json asJson;  
  asJson[PublicKeyJsonFieldName::keyBytes] = toHexStr(publicKeyBytes);
  asJson[PublicKeyJsonFieldName::keyDerivationOptionsJson] =
    keyDerivationOptionsJson;
  return asJson.dump(indent, indent_char);
};


const std::vector<unsigned char> PublicKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::vector<unsigned char> &publicKey,
  const std::string& postDecryptionInstructions
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
    postDecryptionInstructions.c_str(),
    postDecryptionInstructions.length()
  );

  return ciphertext;
}

const std::vector<unsigned char> PublicKey::sealToCiphertextOnly(
  const SodiumBuffer &message,
  const std::vector<unsigned char> &publicKey,
  const std::string& postDecryptionInstructions
) {
  return PublicKey::sealToCiphertextOnly(
    message.data, message.length, publicKey, postDecryptionInstructions
  );
}

const std::vector<unsigned char> PublicKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& postDecryptionInstructions
) const {
  return PublicKey::sealToCiphertextOnly(message, messageLength, publicKeyBytes, postDecryptionInstructions);
}

const std::vector<unsigned char> PublicKey::sealToCiphertextOnly(
  const SodiumBuffer& message,
  const std::string& postDecryptionInstructions
) const {
  return sealToCiphertextOnly(message.data, message.length, postDecryptionInstructions);
}

const PackagedSealedMessage PublicKey::seal(
  const std::vector<unsigned char>& message,
  const std::string& postDecryptionInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message.data(), message.size(), postDecryptionInstructions),
    keyDerivationOptionsJson,
    postDecryptionInstructions
  );  
}

const PackagedSealedMessage PublicKey::seal(
  const SodiumBuffer& message,
  const std::string& postDecryptionInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message.data, message.length, postDecryptionInstructions),
    keyDerivationOptionsJson,
    postDecryptionInstructions
  );
}

const PackagedSealedMessage PublicKey::seal(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& postDecryptionInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message, messageLength, postDecryptionInstructions),
    keyDerivationOptionsJson,
    postDecryptionInstructions
  );
}

  const PackagedSealedMessage PublicKey::seal(
    const std::string& message,
    const std::string& postDecryptionInstructions
  ) const {
    return seal((const unsigned char*) message.c_str(), message.size(), postDecryptionInstructions);
  }

const std::vector<unsigned char> PublicKey::getPublicKeyBytes(
) const {
  return publicKeyBytes;
}

const SodiumBuffer PublicKey::toSerializedBinaryForm() const {
  SodiumBuffer keyDerivationOptionsJsonBuffer = SodiumBuffer(keyDerivationOptionsJson);
  SodiumBuffer _publicKeyBytes(publicKeyBytes);
  SodiumBuffer _keyDerivationOptionsJson(keyDerivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &_publicKeyBytes,
    &_keyDerivationOptionsJson
  });
}

PublicKey PublicKey::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return PublicKey(fields[0].toVector(), fields[1].toUtf8String());
}
