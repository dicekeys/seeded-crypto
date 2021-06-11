#include "OpenPgpKey.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
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
    const ByteBuffer secretPacket = createEd25519SecretKeyPacket(privateKey, publicKey, timestamp);
    const ByteBuffer userPacketBody = createUserPacketBody(userIdPacketContent);
    const ByteBuffer userPacket = createUserPacket(userPacketBody);
    const ByteBuffer signaturePacket = createSignaturePacket(privateKey, publicKey, userPacketBody, timestamp);

    out.append(secretPacket);
    out.append(userPacket);
    out.append(signaturePacket);

    return PEM("PGP PRIVATE KEY BLOCK", out);
}
