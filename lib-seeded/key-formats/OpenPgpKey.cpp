#include <string>
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "SignaturePacket.hpp"
#include "UserPacket.hpp"
#include "PEM.hpp"

std::string generateOpenPgpKey(const ByteBuffer &privateKey, const ByteBuffer &publicKey, const std::string & name, const std::string &email, uint32_t timestamp) {
    ByteBuffer out;
    const ByteBuffer secretPacket = createSecretPacket(privateKey, publicKey, timestamp);
    const ByteBuffer userPacket = createUserPacket(name, email);
    const ByteBuffer signaturePacket = createSignaturePacket(privateKey, publicKey, userPacket, timestamp);

    out.append(secretPacket);
    out.append(userPacket);
    out.append(signaturePacket);

    return PEM("PGP PRIVATE KEY BLOCK", out);
}

//
//const std::string generateOpenPgpKey(u_int8_t privateKey[], std::string name, std::string email, uint32_t timestamp) {
//  std::vector<u_int8_t> out;
//  std::vector<u_int8_t> secretPacket = getSecretPacket(privateKey, timestamp);
//  std::vector<u_int8_t> userPacket = getUserIdPacket(name, email);
//  std::vector<u_int8_t> signaturePacket = signaturePacket(privateKey, timestamp, userPacket);
//  out.insert( out.end(), secretPacket.begin(), secretPacket.end() );
//  out.insert( out.end(), userPacket.begin(), userPacket.end() );
//  out.insert( out.end(), signaturePacket.begin(), signaturePacket.end() );
//}