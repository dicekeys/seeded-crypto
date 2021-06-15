#include "OpenPgpKey.hpp"
#include "EdDsaPublicPacket.hpp"
#include "EdDsaSecretKeyPacket.hpp"
#include "SignaturePacket.hpp"
#include "UserPacket.hpp"
#include "PEM.hpp"

std::string generateOpenPgpKey(
    const SigningKey &signingKey,
    const std::string &userIdPacketContent,
    uint32_t timestamp
) {
    const ByteBuffer privateKey(signingKey.getSeedBytes());
    const ByteBuffer publicKey(signingKey.getSignatureVerificationKeyBytes());

    ByteBuffer out;
    const EdDsaPublicPacket publicKeyPacket(publicKey, timestamp);
    const EdDsaSecretKeyPacket secretPacket(publicKeyPacket, privateKey, timestamp);
    const UserPacket userPacket(userIdPacketContent);
    const SignaturePacket signaturePacket(signingKey, userPacket, secretPacket, publicKeyPacket, timestamp);

    out.append(secretPacket.encode());
    out.append(userPacket.encode());
    out.append(signaturePacket.encode());

    return PEM("PGP PRIVATE KEY BLOCK", out);
}
