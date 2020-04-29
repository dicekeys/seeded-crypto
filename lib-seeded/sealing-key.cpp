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
    const std::vector<unsigned char> &_SealingKeyBytes,
    const std::string& _derivationOptionsJson
  ) : SealingKeyBytes(_SealingKeyBytes), derivationOptionsJson(_derivationOptionsJson) {
    if (SealingKeyBytes.size() != crypto_box_PUBLICKEYBYTES) {
      throw InvalidDerivationOptionValueException("Invalid key size exception");
    }
  }

SealingKey SealingKey::fromJson(const std::string& SealingKeyAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(SealingKeyAsJson);
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
  asJson[SealingKeyJsonFieldName::keyBytes] = toHexStr(SealingKeyBytes);
  asJson[SealingKeyJsonFieldName::derivationOptionsJson] =
    derivationOptionsJson;
  return asJson.dump(indent, indent_char);
};


const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::vector<unsigned char> &SealingKey,
  const std::string& postDecryptionInstructions
) {
  if (SealingKey.size() != crypto_box_PUBLICKEYBYTES) {
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
    SealingKey.data(),
    postDecryptionInstructions.c_str(),
    postDecryptionInstructions.length()
  );

  return ciphertext;
}

const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const SodiumBuffer &message,
  const std::vector<unsigned char> &SealingKey,
  const std::string& postDecryptionInstructions
) {
  return SealingKey::sealToCiphertextOnly(
    message.data, message.length, SealingKey, postDecryptionInstructions
  );
}

const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& postDecryptionInstructions
) const {
  return SealingKey::sealToCiphertextOnly(message, messageLength, SealingKeyBytes, postDecryptionInstructions);
}

const std::vector<unsigned char> SealingKey::sealToCiphertextOnly(
  const SodiumBuffer& message,
  const std::string& postDecryptionInstructions
) const {
  return sealToCiphertextOnly(message.data, message.length, postDecryptionInstructions);
}

const PackagedSealedMessage SealingKey::seal(
  const std::vector<unsigned char>& message,
  const std::string& postDecryptionInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message.data(), message.size(), postDecryptionInstructions),
    derivationOptionsJson,
    postDecryptionInstructions
  );  
}

const PackagedSealedMessage SealingKey::seal(
  const SodiumBuffer& message,
  const std::string& postDecryptionInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message.data, message.length, postDecryptionInstructions),
    derivationOptionsJson,
    postDecryptionInstructions
  );
}

const PackagedSealedMessage SealingKey::seal(
  const unsigned char* message,
  const size_t messageLength,
  const std::string& postDecryptionInstructions
) const {
  return PackagedSealedMessage(
    sealToCiphertextOnly(message, messageLength, postDecryptionInstructions),
    derivationOptionsJson,
    postDecryptionInstructions
  );
}

  const PackagedSealedMessage SealingKey::seal(
    const std::string& message,
    const std::string& postDecryptionInstructions
  ) const {
    return seal((const unsigned char*) message.c_str(), message.size(), postDecryptionInstructions);
  }

const std::vector<unsigned char> SealingKey::getSealingKeyBytes(
) const {
  return SealingKeyBytes;
}

const SodiumBuffer SealingKey::toSerializedBinaryForm() const {
  SodiumBuffer derivationOptionsJsonBuffer = SodiumBuffer(derivationOptionsJson);
  SodiumBuffer _SealingKeyBytes(SealingKeyBytes);
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
