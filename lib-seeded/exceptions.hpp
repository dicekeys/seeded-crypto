#pragma once

#include <stdexcept>

/** @defgroup exceptions Exceptions
 *  Exceptions thrown by this library
 *  @{
 */

/**
 * @brief Thrown when a cryptographic operation fails
 * due to keys or data being corrupted, modified, or of incorrect length.
 */
class CryptographicVerificationFailureException: public std::invalid_argument
{
public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	CryptographicVerificationFailureException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Cryptographic verification failure") {};
};

/**
 * @brief Thrown when a key is specified to be an invalid or incorrect length.
 */
class KeyLengthException: public std::invalid_argument
{
public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	KeyLengthException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid key length") {};
};

/**
 * @brief Thrown when a JSON-string is not valid
 */
class JsonParsingException: public std::invalid_argument
{
public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	JsonParsingException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Exception in parsing JSON") {};
};

/**
 * @brief Thrown when a recipe string is not in
 * valid JSON format and cannot be parsed.
 */
class InvalidRecipeJsonException: public std::invalid_argument
{
	public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	InvalidRecipeJsonException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid JSON key recipe") {};
};

/**
 * @brief Thrown when a JSON value in the recipe is
 * in an invalid format or contains an invalid value.
 */
class InvalidDerivationOptionValueException: public std::invalid_argument
{
	public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	InvalidDerivationOptionValueException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid key recipe") {};
};

/** @} */ // end of Exceptions group