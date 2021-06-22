#include "OpenPgpPacket.hpp"
#include "SecretKeyPacket.hpp"

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey) {
  // https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-crypto-refresh#section-5.5.3
  // 5.5.3.  Secret-Key Packet Formats
  // ...
  // * If the string-to-key usage octet is zero or 255, then a two-octet
  //   checksum of the plaintext of the algorithm-specific portion (sum
  //   of all octets, mod 65536)...
  uint16_t checksum = 0;
  for (size_t i = 0; i < wrappedSecretKey.byteVector.size(); i ++) {
    // arithmetic on two-byte unsigned shorts is already mod 65536
    // so we don't have to perform the mod operation
    const ubyte byte = wrappedSecretKey.byteVector[i];
    checksum += byte;
  }
  return checksum;
}


const ByteBuffer createSecretKeyPacketBody(ubyte version, const ByteBuffer& secretKey, const PublicKeyPacket& publicKeyPacket, uint32_t timestamp) {
  ByteBuffer packetBody;
// 5.5.1.3.  Secret-Key Packet (Tag 5)
//
//    A Secret-Key packet contains all the information that is found in a
//    Public-Key packet, including the public-key material, but also
//    includes the secret-key material after all the public-key fields.
  packetBody.append(publicKeyPacket.body);
  // 5.5.3.  Secret-Key Packet Formats

  //    The Secret-Key and Secret-Subkey packets contain all the data of the
  //    Public-Key and Public-Subkey packets, with additional algorithm-
  //    specific secret-key data appended, usually in encrypted form.
  //
  //    The packet contains:
  //
  //    *  A Public-Key or Public-Subkey packet, as described above.

  //  *  One octet indicating string-to-key usage conventions.  Zero
  //     indicates that the secret-key data is not encrypted. 255 or 254
  //     indicates that a string-to-key specifier is being given.  Any
  //     other value is a symmetric-key encryption algorithm identifier.  A
  //     version 5 packet MUST NOT use the value 255.
  packetBody.writeByte(SECRET_KEY_ENCRYPTION_OFF);

  //  *  Only for a version 5 packet, a one-octet scalar octet count of the
  //     next 4 optional fields.
  if (version == VERSION_5) {
    packetBody.writeByte(0);
  }

  //  *  [Optional] If string-to-key usage octet was 255 or 254, a one-
  //     octet symmetric encryption algorithm.

  //  *  [Optional] If string-to-key usage octet was 255 or 254, a string-
  //     to-key specifier.  The length of the string-to-key specifier is
  //     implied by its type, as described above.

  //  *  [Optional] If secret data is encrypted (string-to-key usage octet
  //     not zero), an Initial Vector (IV) of the same length as the
  //     cipher's block size.

  // Append the actual secret key material, in MPI format as specified above
  const ByteBuffer keyWrappedInMpiFormat = wrapKeyAsMpiFormat(secretKey);

  //  *  Only for a version 5 packet, a four-octet scalar octet count for
  //     the following secret key material.  This includes the encrypted
  //     SHA-1 hash or AEAD tag if the string-to-key usage octet is 254 or
  //     253.
  if (version == VERSION_5) {
    packetBody.write32Bits(
      keyWrappedInMpiFormat.size() +
      2 // checksum, future -- include conditionally only if S2K byte is 0 (no encryption)
      );
  }

  packetBody.append(keyWrappedInMpiFormat);
  // future --  include conditionally only if S2K byte is 0 (no encryption)
  packetBody.write16Bits(calculateCheckSumOfWrappedSecretKey(keyWrappedInMpiFormat));
  return packetBody;
}

SecretKeyPacket::SecretKeyPacket(
  const EdDsaPublicPacket& publicKeyPacket,
  const ByteBuffer& _secretKey,
  uint32_t _timestamp
) : OpenPgpPacket(PTAG_SECRET),
  secretKey(_secretKey),
  timestamp(_timestamp),
  body(createSecretKeyPacketBody(publicKeyPacket.keyConfiguration.version, secretKey, publicKeyPacket, timestamp))
  {}

const ByteBuffer& SecretKeyPacket::getBody() const { return body; };
