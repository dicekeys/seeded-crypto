#pragma once

#include <stdexcept>

class CryptographicVerificationFailure: public std::invalid_argument
{
	public:
	CryptographicVerificationFailure(const char* what) :
		std::invalid_argument(what) {};
};
