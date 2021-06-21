#pragma once

#include <string>
#include "../signing-key.hpp"

std::string generateOpenPgpKey(
        uint8_t version,
        const SigningKey &signingKey,
        const std::string &userIdPacketContent,
        uint32_t timestamp
);
