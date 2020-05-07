
#include <cassert>
#include <exception>
#include "exceptions.hpp"
#include "unsealing-instructions.hpp"

UnsealingInstructions::UnsealingInstructions(
  const std::string& unsealingInstructions
) {
  if (unsealingInstructions.size() == 0) {
    // Empty unsealing instructions
    return;
  }
  // Use the nlohmann::json library to read the JSON-encoded
  // key generation options.
  try {
    nlohmann::json unsealingOptionsObject =
      nlohmann::json::parse(unsealingInstructions);
  
    clientApplicationIdMustHavePrefix =
      unsealingOptionsObject.value<const std::vector<std::string>>(
        UnsealingInstructionsJson::FieldNames::androidPackagePrefixesAllowed,
        // Default to empty list containing the empty string, which is a prefix of all strings
        {""}
      );

    // requireUsersConsent =
    //   unsealingOptionsObject.value<FIXME>(
    //     UnsealingInstructionsJson::FieldNames::requireUsersConsent,
    //     // Default to empty string
    //     ""
    //   );
  } catch (nlohmann::json::exception e) {
    throw JsonParsingException(e.what());
  }

}

UnsealingInstructions::UnsealingInstructions(
		std::vector<std::string> clientApplicationIdMustHavePrefix //,
//		ConsentRequirement requireUsersConsent
) :
  clientApplicationIdMustHavePrefix(clientApplicationIdMustHavePrefix)//,
//  requireUsersConsent(requireUsersConsent)
  {}

std::string	UnsealingInstructions::toJson(int indent,
  const char indent_char
) const {
	nlohmann::json asJson;  
  // asJson[UnsealingInstructionsJson::FieldNames::requireUsersConsent] =
  //   requireUsersConsent;
  asJson[UnsealingInstructionsJson::FieldNames::androidPackagePrefixesAllowed] =
    clientApplicationIdMustHavePrefix;
  return asJson.dump(indent, indent_char);
}

bool UnsealingInstructions::isApplicationIdAllowed(const std::string& applicationId) const {
  if (clientApplicationIdMustHavePrefix.size() == 0) {
    // The applicationId is not required to match a prefix 
    return true;
  }
  // Check to see if the applicationId starts with one of the approved prefixes
  for (const std::string prefix : clientApplicationIdMustHavePrefix) {
    if (applicationId.substr(0, prefix.length()) == prefix) {
      // The applicationId is permitted as it matched this prefix Id
      return true;
    }
  }
  // The applicationId must start with one of the prefixes on the list,
  // but it does not.
  return false;
}

void UnsealingInstructions::validateApplicationId(const std::string& applicationId) const {
  if (!isApplicationIdAllowed(applicationId)) {
    throw std::invalid_argument( ("Invalid application ID: " + applicationId).c_str() );
  }
}
