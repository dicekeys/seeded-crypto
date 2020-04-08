#pragma once

#include <cassert>
#include "hash-functions.hpp"
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "./externally-generated/key-derivation-parameters.hpp"

class PostDecryptionInstructions {
/**
 * This class represents key generation options,
 * provided in JSON format, as an immutable class.
 */

public:
	std::vector<std::string> clientApplicationIdMustHavePrefix;
	std::string userMustAcknowledgeThisMessage;

	/**
	 * Create a PostDecryptionInstructions class from the JSON representation
	 * of the key generation options.
	 **/
	PostDecryptionInstructions(
		const std::string &postDecryptionInstructionsJson
	);

	PostDecryptionInstructions(
		std::vector<std::string> clientApplicationIdMustHavePrefix,
		std::string userMustAcknowledgeThisMessage = {}
	);

	bool isApplicationIdAllowed(const std::string &applicationId) const;
	void validateApplicationId(const std::string &applicationId) const;

	std::string	toJson(
		int indent = -1,
	  const char indent_char = ' '
	) const;
};
