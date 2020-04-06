#pragma once

#include <stdexcept>

/**
 * @brief Thrown when a cryptographic operation fails
 * due to keys or data being corrupted, modified, or of incorrect length.
 */
class CryptographicVerificationFailure: public std::invalid_argument
{
public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	CryptographicVerificationFailure(const char* m = NULL) :
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
 * @brief Thrown when a keyDerivationOptionsJson string is not in
 * valid JSON format and cannot be parsed.
 */
class InvalidKeyDerivationOptionsJsonException: public std::invalid_argument
{
	public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	InvalidKeyDerivationOptionsJsonException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid JSON key derivation options") {};
};

/**
 * @brief Thrown when a JSON value in the keyDerivationOptionsJson is
 * in an invalid format or contains an invalid value.
 */
class InvalidKeyDerivationOptionValueException: public std::invalid_argument
{
	public:
	/**
	 * @brief Construct by throwing, passing an optional exception message
	 * 
	 * @param m The exception message
	 */
	InvalidKeyDerivationOptionValueException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid key derivation options") {};
};
