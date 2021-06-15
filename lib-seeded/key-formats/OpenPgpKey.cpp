#include "OpenPgpKey.hpp"
#include "EdDsaPublicPacket.hpp"
#include "EdDsaSecretKeyPacket.hpp"
#include "SignaturePacket.hpp"
#include "UserPacket.hpp"
#include "PEM.hpp"

// https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-11.1
//   11.1.  Transferable Public Keys
//
//    OpenPGP users may transfer public keys.  The essential elements of a
//    transferable public key are as follows:
//
//    *  One Public-Key packet
//
//    *  Zero or more revocation signatures
//
//    *  One or more User ID packets
//
//    *  After each User ID packet, zero or more Signature packets
//       (certifications)
//
//    *  Zero or more User Attribute packets
//
//    *  After each User Attribute packet, zero or more Signature packets
//       (certifications)
//
//    *  Zero or more Subkey packets
//
//    *  After each Subkey packet, one Signature packet, plus optionally a
//       revocation
//
//    The Public-Key packet occurs first.  Each of the following User ID
//    packets provides the identity of the owner of this public key.  If
//    there are multiple User ID packets, this corresponds to multiple
//    means of identifying the same unique individual user; for example, a
//    user may have more than one email address, and construct a User ID
//    for each one.
//
//    Immediately following each User ID packet, there are zero or more
//    Signature packets.  Each Signature packet is calculated on the
//    immediately preceding User ID packet and the initial Public-Key
//    packet.  The signature serves to certify the corresponding public key
//    and User ID.  In effect, the signer is testifying to his or her
//    belief that this public key belongs to the user identified by this
//    User ID.
//
//    Within the same section as the User ID packets, there are zero or
//    more User Attribute packets.  Like the User ID packets, a User
//    Attribute packet is followed by zero or more Signature packets
//    calculated on the immediately preceding User Attribute packet and the
//    initial Public-Key packet.
//
//    User Attribute packets and User ID packets may be freely intermixed
//    in this section, so long as the signatures that follow them are
//    maintained on the proper User Attribute or User ID packet.
//
//    After the User ID packet or Attribute packet, there may be zero or
//    more Subkey packets.  In general, subkeys are provided in cases where
//    the top-level public key is a signature-only key.  However, any V4 or
//    V5 key may have subkeys, and the subkeys may be encryption-only keys,
//    signature-only keys, or general-purpose keys.  V3 keys MUST NOT have
//    subkeys.
//
//    Each Subkey packet MUST be followed by one Signature packet, which
//    should be a subkey binding signature issued by the top-level key.
//    For subkeys that can issue signatures, the subkey binding signature
//    MUST contain an Embedded Signature subpacket with a primary key
//    binding signature (0x19) issued by the subkey on the top-level key.
//
//    Subkey and Key packets may each be followed by a revocation Signature
//    packet to indicate that the key is revoked.  Revocation signatures
//    are only accepted if they are issued by the key itself, or by a key
//    that is authorized to issue revocations via a Revocation Key
//    subpacket in a self-signature by the top-level key.
//
//    Transferable public-key packet sequences may be concatenated to allow
//    transferring multiple public keys in one operation.


//   11.2.  Transferable Secret Keys

//    OpenPGP users may transfer secret keys.  The format of a transferable
//    secret key is the same as a transferable public key except that
//    secret-key and secret-subkey packets are used instead of the public
//    key and public-subkey packets.  Implementations SHOULD include self-
//    signatures on any User IDs and subkeys, as this allows for a complete
//    public key to be automatically extracted from the transferable secret
//    key.  Implementations MAY choose to omit the self-signatures,
//    especially if a transferable public key accompanies the transferable
//    secret key.
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
