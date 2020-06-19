#include "secret.hpp"
#include "derivation-options.hpp"
#include "exceptions.hpp"

Secret::Secret(
  const SodiumBuffer& _secretBytes,
  const std::string& _derivationOptionsJson
) : secretBytes(_secretBytes), derivationOptionsJson(_derivationOptionsJson) {}

Secret::Secret(
  const std::string& seedString,
  const std::string& _derivationOptionsJson
) : secretBytes(
  DerivationOptions::derivePrimarySecret(
    seedString,
    _derivationOptionsJson,
    DerivationOptionsJson::type::Secret
  )), derivationOptionsJson(_derivationOptionsJson) {}

Secret Secret::deriveFromSeed(
  const std::string& seedString,
  const std::string& derivationOptionsJson
) {
  return Secret(
    DerivationOptions::derivePrimarySecret(
      seedString,
      derivationOptionsJson,
      DerivationOptionsJson::type::Secret
    ),
    derivationOptionsJson
  );
}


Secret::Secret(const Secret &other) : Secret(other.secretBytes, other.derivationOptionsJson) {}

// JSON field names
namespace SecretJsonFields {
  static const std::string secretBytes = "secretBytes";
  static const std::string derivationOptionsJson = "derivationOptionsJson";
}

Secret Secret::fromJson(const std::string& secretAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(secretAsJson);
    auto kdo = jsonObject.value<std::string>(SecretJsonFields::derivationOptionsJson, "");
    return Secret(
      SodiumBuffer::fromHexString(jsonObject.at(SecretJsonFields::secretBytes)),
      jsonObject.value<std::string>(SecretJsonFields::derivationOptionsJson, "")
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
  if (derivationOptionsJson.size() > 0) {
    asJson[SecretJsonFields::derivationOptionsJson] = derivationOptionsJson;
  }
  return asJson.dump(indent, indent_char);
}


const SodiumBuffer Secret::toSerializedBinaryForm() const {
  SodiumBuffer _derivationOptionsJson(derivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &secretBytes,
    &_derivationOptionsJson
  });
}

Secret Secret::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return Secret(fields[0], fields[1].toUtf8String());
}
