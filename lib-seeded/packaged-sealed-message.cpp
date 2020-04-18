#include "packaged-sealed-message.hpp"
#include "github-com-nlohmann-json/json.hpp"
#include "exceptions.hpp"
#include "convert.hpp"

// JSON field names
namespace PackagedSealedMessageJsonFields {
  static const std::string ciphertext = "ciphertext";
  static const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
  static const std::string postDecryptionInstructions = "postDecryptionInstructions";
}

PackagedSealedMessage::PackagedSealedMessage(
        const std::vector<unsigned char>& _ciphertext,
        const std::string& _keyDerivationOptionsJson,
        const std::string& _postDecryptionInstructions
) : 
    ciphertext(_ciphertext),
    keyDerivationOptionsJson(_keyDerivationOptionsJson),
    postDecryptionInstructions(_postDecryptionInstructions)
    {}

PackagedSealedMessage::PackagedSealedMessage(const PackagedSealedMessage &other) :
  ciphertext(other.ciphertext),
  keyDerivationOptionsJson(other.keyDerivationOptionsJson),
  postDecryptionInstructions(other.postDecryptionInstructions)
  {}

const SodiumBuffer PackagedSealedMessage::toSerializedBinaryForm() const {
  SodiumBuffer _ciphertext(ciphertext);
  SodiumBuffer _keyDerivationOptionsJson(keyDerivationOptionsJson);
  SodiumBuffer _postDecryptionInstructions(postDecryptionInstructions);
  return SodiumBuffer::combineFixedLengthList({
    &_ciphertext,
    &_keyDerivationOptionsJson,
    &_postDecryptionInstructions
  });
}

PackagedSealedMessage PackagedSealedMessage::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(3);
  return PackagedSealedMessage(fields[0].toVector(), fields[1].toUtf8String(), fields[2].toUtf8String());
}

const std::string PackagedSealedMessage::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[PackagedSealedMessageJsonFields::ciphertext] = toHexStr(ciphertext);
  if (keyDerivationOptionsJson.size() > 0) {
    asJson[PackagedSealedMessageJsonFields::keyDerivationOptionsJson] = keyDerivationOptionsJson;
  }
  if (postDecryptionInstructions.size() > 0) {
    asJson[PackagedSealedMessageJsonFields::postDecryptionInstructions] = postDecryptionInstructions;
  }
  return asJson.dump(indent, indent_char);
}
  
PackagedSealedMessage PackagedSealedMessage::fromJson(const std::string& packagedSealedMessageAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(packagedSealedMessageAsJson);
    auto kdo = jsonObject.value<std::string>(PackagedSealedMessageJsonFields::keyDerivationOptionsJson, "");
    return PackagedSealedMessage(
      hexStrToByteVector(jsonObject.at(PackagedSealedMessageJsonFields::ciphertext)),
      jsonObject.value<std::string>(PackagedSealedMessageJsonFields::keyDerivationOptionsJson, ""),
      jsonObject.value<std::string>(PackagedSealedMessageJsonFields::postDecryptionInstructions, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}
