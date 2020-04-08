#include "./seed.hpp"
#include "generate-seed.hpp"

Seed::Seed(
  const SodiumBuffer& _seedBytes,
  const std::string& _keyDerivationOptionsJson
) : seedBytes(_seedBytes), keyDerivationOptionsJson(_keyDerivationOptionsJson) {}

Seed::Seed(
  const std::string& seedString,
  const std::string& _keyDerivationOptionsJson
) : Seed(
  generateSeed(
    seedString,
    _keyDerivationOptionsJson,
    KeyDerivationOptionsJson::KeyType::Seed
  ),
  _keyDerivationOptionsJson
) {}

Seed::Seed(const Seed &other) : Seed(other.seedBytes, other.keyDerivationOptionsJson) {}

Seed::Seed(const std::string &seedAsJson) : Seed(Seed::fromJson(seedAsJson)) {}

// JSON field names
namespace SeedJsonFields {
  static const std::string seedBytes = "seedBytes";
  static const std::string keyDerivationOptionsJson = "keyDerivationOptionsJson";
}

Seed Seed::fromJson(const std::string &seedAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(seedAsJson);
    auto kdo = jsonObject.value<std::string>(SeedJsonFields::keyDerivationOptionsJson, std::string());
    return Seed(
      SodiumBuffer::fromHexString(jsonObject.at(SeedJsonFields::seedBytes)),
      jsonObject.value<std::string>(SeedJsonFields::keyDerivationOptionsJson, std::string())
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}

const std::string
Seed::toJson(
  int indent,
const char indent_char
) const {
  nlohmann::json asJson;
  asJson[SeedJsonFields::seedBytes] = seedBytes.toHexString();
  if (keyDerivationOptionsJson.size() > 0) {
    asJson[SeedJsonFields::keyDerivationOptionsJson] = keyDerivationOptionsJson;
  }
  return asJson.dump(indent, indent_char);
}


const SodiumBuffer Seed::toSerializedBinaryForm() const {
  SodiumBuffer keyDerivationOptionsJsonBuffer = SodiumBuffer(keyDerivationOptionsJson);
  return SodiumBuffer::combineFixedLengthList({
    &seedBytes,
    &SodiumBuffer(keyDerivationOptionsJson)
  });
}

Seed Seed::fromSerializedBinaryForm(SodiumBuffer serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return Seed(fields[0], fields[1].toUtf8String());
}
