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
//    const ByteBuffer secretPacket = createEd25519EdDsaSecretKeyPacket(privateKey, publicKeyPacket, timestamp);
    const UserPacket userPacket(userIdPacketContent);
//    const ByteBuffer userPacketBody = createUserPacketBody(userIdPacketContent);
//    const ByteBuffer userPacket = createUserPacket(userPacketBody);
    const ByteBuffer signaturePacket = createSignaturePacket(privateKey, publicKeyPacket, userPacket, timestamp);

    out.append(secretPacket.encode());
    out.append(userPacket.encode());
    out.append(signaturePacket);

    return PEM("PGP PRIVATE KEY BLOCK", out);
}
