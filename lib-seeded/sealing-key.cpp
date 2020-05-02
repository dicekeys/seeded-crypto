#include "github-com-nlohmann-json/json.hpp"
#include "sealing-key.hpp"
#include "crypto_box_seal_salted.h"
#include "convert.hpp"
#include "lib-seeded.hpp"
#include "exceptions.hpp"

namespace SealingKeyJsonFieldName {
  const std::string keyBytes = "keyBytes";
  const std::string derivationOptionsJson = "derivationOptionsJson";
}

SealingKey::SealingKey(
    const std::vector<unsigned char> &_sealingKeyBytes,
    const std::string& _derivationOptionsJson
  ) : sealingKeyBytes(_sealingKeyBytes), derivationOptionsJson(_derivationOptionsJson) {
    if (sealingKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw InvalidDerivationOptionValueException("Invalid key size exception");
    }
  }

SealingKey SealingKey::fromJson(const std::string& sealingKeyAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(sealingKeyAsJson);
    return SealingKey(
      hexStrToByteVector(jsonObject.at(SealingKeyJsonFieldName::keyBytes)),
      jsonObject.value(SealingKeyJsonFieldName::derivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string SealingKey::toJson(
  int indent,
  const char indent_char
) const {
	nlohmann::json asJson;  
  asJson[SealingKeyJsonFieldName::keyBytes] = toHexStr(sealingKeyBytes);
  asJson[SealingKeyJsonFieldName::derivationOptionsJson] =
    derivationOptionsJson;
  return asJson.dump(indent, indent_char);
};


const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::vector<unsigned char> &sealingKeyBytes,
  const std::string& unsealingInstructions
) {
  if (sealingKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
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
    sealingKeyBytes.data(),
    unsealingInstructions.c_str(),
    unsealingInstructions.length()
  );

  return ciphertext;
}

const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const SodiumBuffer &message,
  const std::vector<unsigned char> &sealingKeyBytes,
  const std::string& unsealingInstructions
) {
  return SealingKey::sealToCiphertextOnly(
    message.data, message.length, sealingKeyBytes, unsealingInstructions
  );
}

const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& unsealingInstructions
) const {
  return SealingKey::sealToCiphertextOnly(message, messageLength, sealingKeyBytes, unsealingInstructions);
}

const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const SodiumBuffer& message,
  const std::string& unsealingInstructions
) const {
  return sealToCiphertextOnly(message.data, message.length, unsealingInstructions);
}

const PackagedSealedMessage SealingKey::seal(
  const std::vector<unsigned char>& message,
  const std::string& unsealingInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message.data(), message.size(), unsealingInstructions),
    derivationOptionsJson,
    unsealingInstructions
  );  
}

const PackagedSealedMessage SealingKey::seal(
  const SodiumBuffer& message,
  const std::string& unsealingInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message.data, message.length, unsealingInstructions),
    derivationOptionsJson,
    unsealingInstructions
  );
}

const PackagedSealedMessage SealingKey::seal(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& unsealingInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message, messageLength, unsealingInstructions),
    derivationOptionsJson,
    unsealingInstructions
  );
}

  const PackagedSealedMessage SealingKey::seal(
    const std::string& message,
    const std::string& unsealingInstructions
  ) const {
    return seal((const unsigned char*) message.c_str(), message.size(), unsealingInstructions);
  }

const std::vector<unsigned char> SealingKey::getSealingKeyBytes(
) const {
  return sealingKeyBytes;
}

const SodiumBuffer SealingKey::toSerializedBinaryForm() const {
  SodiumBuffer derivationOptionsJsonBuffer = SodiumBuffer(derivationOptionsJson);
  SodiumBuffer _SealingKeyBytes(sealingKeyBytes);
  SodiumBuffer _derivationOptionsJson(derivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &_SealingKeyBytes,
    &_derivationOptionsJson
  });
}

SealingKey SealingKey::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return SealingKey(fields[0].toVector(), fields[1].toUtf8String());
}
