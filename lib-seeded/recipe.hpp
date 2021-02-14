#pragma once

#ifndef EMSCRIPTEN
 #pragma warning( disable : 26812 )
#endif
#include "github-com-nlohmann-json/json.hpp"
// Must come after json.hpp
#include "./externally-generated/derivation-parameters.hpp"
#include "recipe.hpp"

const size_t BytesPerWordOfPassword = 8;



/**
 * @brief This class parses a recipe string
 * on construction and then exposes the
 * @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
 * as fields of this class.
 * 
 * @ingroup BuildingBlocks
 */
class Recipe {
/**
 * This class represents key generation options,
 * provided in JSON format, as an immutable class.
 */

private:
	nlohmann::json recipeExplicit;
public:
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
	RecipeJson::Algorithm algorithm;
	/**
	 * @brief The original JSON string used to construct this object
	 */
	const std::string recipe;

	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
	RecipeJson::type type;

	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
  	unsigned int lengthInBytes = 0;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
		unsigned int lengthInBits = 0;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
		size_t lengthInChars = -1;
		/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
		unsigned int lengthInWords = 0;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
		RecipeJson::WordList wordList = RecipeJson::WordList::_INVALID_WORD_LIST_;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
	size_t hashFunctionMemoryLimitInBytes;
	/**
	 * @brief Mirroring the JSON field in @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
	size_t hashFunctionMemoryPasses;

	/**
	 * @brief The name of the hash function specified in the @ref derivation_options_universal_fields "Recipe JSON Universal Fields"
	 */
	RecipeJson::HashFunction hashFunction;

	/**
	 * Create a Recipe class from the JSON representation
	 * of the key generation options.
	 * 
	 * @param recipe The JSON formatted recipe object to parse
	 * as specified by @ref recipe_format
	 * @param typeRequired The required type, which will be the default if the JSON doesn't
	 * contain a type field and which will cause an exception to be thrown if the
	 * JSON has a conflicting type.  If not set
	 * (default: RecipeJson::type::_INVALID_TYPE_)
	 * there is no required type and any type is allowed.
	 * @throws InvalidRecipeJsonException
	 * @throws InvalidDerivationOptionValueException
	 **/
	Recipe(
		const std::string& recipe,
		const RecipeJson::type typeRequired =
			RecipeJson::type::_INVALID_TYPE_
	);

	/**
	 * @brief Return JSON with default parameters filled in.
	 *
	 * @param indent JSON indent depth
	 * @param indent_char The char used for JSON indenting
	 */
	const std::string recipeWithAllOptionalParametersSpecified(
		int indent = -1,
	  const char indent_char = ' '
	) const;

	/**
	 * @brief This function derives the master secrets for SymmetricKey,
	 * for the SealingKey and UnsealingKey pair,
	 * for the SignatureVerificationKey and SigningKey pair,
	 * and for the general-purpose Secret class.
	 * 
	 * It applies the hash function specified in the recipe
	 * to a preimage of the following form:
	 * ```
	 *   <seedString> + '\0' + <typeRequired> + <recipe>
	 * ```
	 * where typeRequired is converted to a string in
	 * ["Secret", "SymmetricKey", "UnsealingKey", "SigningKey"],
	 * based on the value of the typeRequired parameter.
	 * 
	 *   * For "Secret", the generated secret is placed directly into the
	 *     `secretBytes` field of the Secret class.
	 *   * For "SymmetricKey", the generated secret becomes the `keyBytes` field
	 *     of the SymmetricKey class.
	 *   * For "UnsealingKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_box_seed_keypair` function, which generates
	 *     the key bytes for the UnsealingKey and SealingKey.
	 *   * For "SigningKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_sign_seed_keypair` function, which generates
	 *     the key bytes for the SigningKey and SignatureVerificationKey..
	 * 
	 * @param seedString A seed value that is the primary salt for the hash function
	 * @param recipe The recipe in @ref recipe_format.
	 * @param typeRequired If the recipe has a type field, and that field
	 * specifies a value other than this typeRequired value, this function will throw an
	 * InvalidDerivationOptionValueException.
	 * @param lengthInBytesRequired If the recipe does not specify a lengthInBytes,
	 * generate a secret of this length. Throw an InvalidDerivationOptionValueException is
	 * the lengthInBytes it specifies does not match this value.
	 * @return const SodiumBuffer The derived secret, set to always be a const so that it is never
	 * modified directly.
	 * 
	 * @throw InvalidDerivationOptionValueException
	 * @throw InvalidRecipeJsonException
	 */
	static const SodiumBuffer derivePrimarySecret(
		const std::string& seedString,
		const std::string& recipe,
		const RecipeJson::type typeRequired = RecipeJson::type::_INVALID_TYPE_,
		const size_t lengthInBytesRequired = 0
	);

	/**
	 * @brief This function derives the master secrets for SymmetricKey,
	 * for the SealingKey and UnsealingKey pair,
	 * for the SignatureVerificationKey and SigningKey pair,
	 * and for the general-purpose Secret class.
	 * 
	 * It applies the hash function specified in the recipe
	 * to a preimage of the following form:
	 * ```
	 *   <seedString> + '\0' + <type> + <recipe>
	 * ```
	 * where type is converted to a string in
	 * ["Secret", "SymmetricKey", "UnsealingKey", "SigningKey"],
	 * based on the value of the type parameter,
	 * defaultType if type is not set (_INVALID_TYPE_),
	 * or "" if neither is set (both are _INVALID_TYPE_).
	 * 
	 *   * For "Secret" and "Password", the generated secret is placed directly into the
	 *     `secretBytes` field of the Secret class.
	 *   * For "SymmetricKey", the generated secret becomes the `keyBytes` field
	 *     of the SymmetricKey class.
	 *   * For "UnsealingKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_box_seed_keypair` function, which generates
	 *     the key bytes for the UnsealingKey and SealingKey.
	 *   * For "SigningKey", the generated secret is the final parameter (input) to
	 *     libsodium's `crypto_sign_seed_keypair` function, which generates
	 *     the key bytes for the SigningKey and SignatureVerificationKey..
	 * 
	 * @param seedString A seed value that is the primary salt for the hash function
	 * @param defaultType If the recipe has a type field, and that field
	 * specifies a value other than this typeRequired value, this function will throw an
	 * InvalidDerivationOptionValueException.
	 * @return const SodiumBuffer The derived secret, set to always be a const so that it is never
	 * modified directly.
	 * 
	 * @throw InvalidDerivationOptionValueException
	 */
	const SodiumBuffer derivePrimarySecret(
		const std::string& seedString,
		const RecipeJson::type defaultType =
			RecipeJson::type::_INVALID_TYPE_
	) const;

};
