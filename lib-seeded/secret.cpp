#include "secret.hpp"
#include "recipe.hpp"
#include "exceptions.hpp"
#include "common-names.hpp"

Secret::Secret(
  const SodiumBuffer& _secretBytes,
  const std::string& _recipe
) : secretBytes(_secretBytes), recipe(_recipe) {}

Secret::Secret(
  const std::string& seedString,
  const std::string& _recipe
) : secretBytes(
  Recipe::derivePrimarySecret(
    seedString,
    _recipe,
    RecipeJson::type::Secret
  )), recipe(_recipe) {}

Secret Secret::deriveFromSeed(
  const std::string& seedString,
  const std::string& recipe
) {
  return Secret(
    Recipe::derivePrimarySecret(
      seedString,
      recipe,
      RecipeJson::type::Secret
    ),
    recipe
  );
}


Secret::Secret(const Secret &other) : Secret(other.secretBytes, other.recipe) {}

// JSON field names
namespace SecretJsonFields {
  static const std::string secretBytes = "secretBytes";
  static const std::string recipe = CommonNames::recipe;
}

Secret Secret::fromJson(const std::string& secretAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(secretAsJson);
    return Secret(
      SodiumBuffer::fromHexString(jsonObject.at(SecretJsonFields::secretBytes)),
      jsonObject.value<std::string>(SecretJsonFields::recipe, "")
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
  if (recipe.size() > 0) {
    asJson[SecretJsonFields::recipe] = recipe;
  }
  return asJson.dump(indent, indent_char);
}


const SodiumBuffer Secret::toSerializedBinaryForm() const {
  SodiumBuffer _recipe(recipe);
  return SodiumBuffer::combineFixedLengthList({
    &secretBytes,
    &_recipe
  });
}

Secret Secret::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(2);
  return Secret(fields[0], fields[1].toUtf8String());
}
