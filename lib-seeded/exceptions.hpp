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
