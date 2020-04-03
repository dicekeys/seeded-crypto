#pragma once

#include <stdexcept>

class CryptographicVerificationFailure: public std::invalid_argument
{
public:
	CryptographicVerificationFailure(const char* what) :
		std::invalid_argument(what) {};
};

class JsonParsingException: public std::invalid_argument
{
public:
	JsonParsingException(const char* what) :
		std::invalid_argument(what) {};
};
