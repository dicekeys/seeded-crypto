#pragma once

#include <string>
#include "../signing-key.hpp"
#include "KeyConfiguration.hpp"
#include "SignaturePacket.hpp"

std::string generateOpenPgpKey(
        const SigningKey &signingKey,
        const std::string &userIdPacketContent,
        uint32_t timestamp,
        const EdDsaKeyConfiguration &configuration = EdDsaKeyConfiguration(),
        const ubyte signatureType = SIGNATURE_TYPE_USER_ID_AND_PUBLIC_KEY_GENERIC
);
