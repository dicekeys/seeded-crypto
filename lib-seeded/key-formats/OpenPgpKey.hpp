#pragma once

#include <string>
#include "../signing-key.hpp"

std::string generateOpenPgpKey(
        const SigningKey &signingKey,
        const std::string &name,
        const std::string &email,
        uint32_t timestamp
);
