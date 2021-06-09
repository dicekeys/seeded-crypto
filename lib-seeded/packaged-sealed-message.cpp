#include "packaged-sealed-message.hpp"
#include "github-com-nlohmann-json/json.hpp"
#include "exceptions.hpp"
#include "convert.hpp"
#include "common-names.hpp"

// JSON field names
namespace PackagedSealedMessageJsonFields {
  static const std::string ciphertext = "ciphertext";
  static const std::string recipe = CommonNames::recipe;
  static const std::string unsealingInstructions = "unsealingInstructions";
}

PackagedSealedMessage::PackagedSealedMessage(
        const std::vector<unsigned char>& _ciphertext,
        const std::string& _recipe,
        const std::string& _unsealingInstructions
) : 
    ciphertext(_ciphertext),
    recipe(_recipe),
    unsealingInstructions(_unsealingInstructions)
    {}

PackagedSealedMessage::PackagedSealedMessage(const PackagedSealedMessage &other) :
  ciphertext(other.ciphertext),
  recipe(other.recipe),
  unsealingInstructions(other.unsealingInstructions)
  {}

const SodiumBuffer PackagedSealedMessage::toSerializedBinaryForm() const {
  SodiumBuffer _ciphertext(ciphertext);
  SodiumBuffer _recipe(recipe);
  SodiumBuffer _unsealingInstructions(unsealingInstructions);
  return SodiumBuffer::combineFixedLengthList({
    &_ciphertext,
    &_recipe,
    &_unsealingInstructions
  });
}

PackagedSealedMessage PackagedSealedMessage::fromSerializedBinaryForm(const SodiumBuffer &serializedBinaryForm) {
  const auto fields = serializedBinaryForm.splitFixedLengthList(3);
  return PackagedSealedMessage(fields[0].toVector(), fields[1].toUtf8String(), fields[2].toUtf8String());
}

const std::string PackagedSealedMessage::toJson(
  int indent,
  const char indent_char
) const {
  nlohmann::json asJson;
  asJson[PackagedSealedMessageJsonFields::ciphertext] = toHexStr(ciphertext);
  if (recipe.size() > 0) {
    asJson[PackagedSealedMessageJsonFields::recipe] = recipe;
  }
  if (unsealingInstructions.size() > 0) {
    asJson[PackagedSealedMessageJsonFields::unsealingInstructions] = unsealingInstructions;
  }
  return asJson.dump(indent, indent_char);
}
  
PackagedSealedMessage PackagedSealedMessage::fromJson(const std::string& packagedSealedMessageAsJson) {
  try {
    nlohmann::json jsonObject = nlohmann::json::parse(packagedSealedMessageAsJson);
    return PackagedSealedMessage(
      hexStrToByteVector(jsonObject.at(PackagedSealedMessageJsonFields::ciphertext)),
      jsonObject.value<std::string>(PackagedSealedMessageJsonFields::recipe, ""),
      jsonObject.value<std::string>(PackagedSealedMessageJsonFields::unsealingInstructions, "")
    );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }
}
