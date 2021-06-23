#pragma once

#include "ByteBuffer.hpp"
#include "PublicKeyPacket.hpp"
#include "SecretKeyPacket.hpp"
#include "UserPacket.hpp"

// 0x02: Standalone signature.
//       This signature is a signature of only its own subpacket contents.
//       It is calculated identically to a signature over a zero-length
//       binary document.  Note that it doesn't make sense to have a V3
//       standalone signature.
const ubyte SIGNATURE_TYPE_STANDALONE = 0x02;
// 0x10: Generic certification of a User ID and Public-Key packet.
const ubyte SIGNATURE_TYPE_USER_ID_AND_PUBLIC_KEY_GENERIC = 0x10;
// 0x13: Positive certification of a User ID and Public-Key packet.
//       The issuer of this certification has done substantial verification
//       of the claim of identity.  Most OpenPGP implementations make their
//       "key signatures" as 0x10 certifications.  Some implementations can
//       issue 0x11-0x13 certifications, but few differentiate between the
//       types.
const ubyte SIGNATURE_TYPE_USER_ID_AND_PUBLIC_KEY_POSITIVE = 0x13;

/**
 * @brief A class representing an OpenPGP Signature Packet
 * 
 * 5.2.  Signature Packet (Tag 2)
 *
 * A Signature packet describes a binding between some public key and
 * some data.  The most common signatures are a signature of a file or a
 * block of text, and a signature that is a certification of a User ID.
 *
 * Implementations MUST generate version 5 signatures when using a
 * version 5 key.  Implementations SHOULD generate V4 signatures with
 * version 4 keys.  Implementations MUST NOT create version 3
 * signatures; they MAY accept version 3 signatures.
 * 
 */
class SignaturePacket : public OpenPgpPacket {
public:
  const ubyte signatureType;
  const uint32_t timestamp;
  const ByteBuffer packetBodyIncludedInSignatureHash;
  const ByteBuffer signatureHashPreImage;
  const ByteBuffer signatureHashSha256;
  const ByteBuffer signature;
  const ByteBuffer unhashedSubpacketsWithSizePrefix;
  const ByteBuffer body;

  SignaturePacket(
    const ubyte signatureType,
    const SigningKey& signingKey,
    const UserPacket& userPacket,
    const PublicKeyPacket& publicKeyPacket,
    uint32_t _timestamp
  );

  const ByteBuffer& getBody() const override;

};