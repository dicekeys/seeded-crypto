#include "OpenPgpKey.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "SignaturePacket.hpp"
#include "UserPacket.hpp"
#include "PEM.hpp"

std::string generateOpenPgpKey(
    const SigningKey &signingKey,
    const std::string &name,
    const std::string &email,
    uint32_t timestamp
) {
    const ByteBuffer privateKey(signingKey.signingKeyBytes);
    const ByteBuffer &publicKey(signingKey.getSignatureVerificationKeyBytes());

    ByteBuffer out;
    const ByteBuffer secretPacket = createSecretPacket(privateKey, publicKey, timestamp);
    const ByteBuffer userPacket = createUserPacket(name, email);
    const ByteBuffer signaturePacket = createSignaturePacket(privateKey, publicKey, userPacket, timestamp);

    out.append(secretPacket);
    out.append(userPacket);
    out.append(signaturePacket);

    return PEM("PGP PRIVATE KEY BLOCK", out);
}
