#include "secret.hpp"
#include "key-derivation-options.hpp"
#include "exceptions.hpp"

Secret::Secret(
  const SodiumBuffer& _secretBytes,
  const std::string& _keyDerivationOptionsJson
) : secretBytes(_secretBytes), keyDerivationOptionsJson(_keyDerivationOptionsJson) {}

Secret::Secret(
  const std::string& seedString,
  const std::string& _keyDerivationOptionsJson
) : Secret(
  KeyDerivationOptions::deriveMasterSecret(
    seedString,
    _keyDerivationOptionsJson,
    KeyDerivationOptionsJson::KeyType::Secret
  ),
  _keyDerivationOptionsJson
) {}

Secret::Secret(const Secret &other) : Secret(other.secretBytes, other.keyDerivationOptionsJson) {}

// JSON field names
namespace SecretJsonFields {
  static const std::string secretBytes = "secretBytes";
  static const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

Secret Secret::fromJson(const std::string& secretAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(secretAsJson);
    auto kdo = jsonObject.value<std::string>(SecretJsonFields::keyDerivationOptionsJson, "");
    return Secret(
      SodiumBuffer::fromHexString(jsonObject.at(SecretJsonFields::secretBytes)),
      jsonObject.value<std::string>(SecretJsonFields::keyDerivationOptionsJson, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string
Secret::toJson(
  int indent,
const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SecretJsonFields::secretBytes] = secretBytes.toHexString();
  if (keyDerivationOptionsJson.size() > 0) {
    asJson[SecretJsonFields::keyDerivationOptionsJson] = keyDerivationOptionsJson;
  }
  return asJson.dump(indent, indent_char);
}


const SodiumBuffer Secret::toSerializedBinaryForm() const {
  SodiumBuffer _keyDerivationOptionsJson(keyDerivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &secretBytes,
    &_keyDerivationOptionsJson
  });
}

Secret Secret::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return Secret(fields[0], fields[1].toUtf8String());
}
