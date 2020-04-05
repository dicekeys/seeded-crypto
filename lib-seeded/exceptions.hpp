#pragma once

#include <stdexcept>

class CryptographicVerificationFailure: public std::invalid_argument
{
public:
	CryptographicVerificationFailure(const char* m = NULL) :
		std::invalid_argument(m ? m : "Cryptographic verification failure") {};
};

class JsonParsingException: public std::invalid_argument
{
public:
	JsonParsingException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Exception in parsing JSON") {};
};

class ClientNotAuthorizedException: public std::invalid_argument
{
	public:
	ClientNotAuthorizedException(const char* m = NULL) :
		std::invalid_argument(m ? m : "The client is not authorized to use this key") {};
};

class InvalidKeyDerivationOptionsJsonException: public std::invalid_argument
{
	public:
	InvalidKeyDerivationOptionsJsonException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid JSON key derivation options") {};
};

class InvalidKeyDerivationOptionValueException: public std::invalid_argument
{
	public:
	InvalidKeyDerivationOptionValueException(const char* m = NULL) :
		std::invalid_argument(m ? m : "Invalid key derivation options") {};
};
