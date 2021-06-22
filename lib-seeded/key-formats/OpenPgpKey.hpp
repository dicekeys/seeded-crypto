#pragma once

#include <string>
#include "../signing-key.hpp"
#include "KeyConfiguration.hpp"

std::string generateOpenPgpKey(
        const SigningKey &signingKey,
        const std::string &userIdPacketContent,
        uint32_t timestamp,
        const EdDsaKeyConfiguration &configuration = EdDsaKeyConfiguration()
);
