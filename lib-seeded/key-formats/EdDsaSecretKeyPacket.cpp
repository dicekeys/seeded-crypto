#include "OpenPgpPacket.hpp"
#include "EdDsaSecretKeyPacket.hpp"

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
    const uint8_t byte = wrappedSecretKey.byteVector[i];
    checksum += byte;
  }
  return checksum;
}


const ByteBuffer createEd25519EdDsaSecretKeyPacketBody(const ByteBuffer& secretKey, const EdDsaPublicPacket& publicKeyPacket, uint32_t timestamp) {
  ByteBuffer packetBody;
// 5.5.1.3.  Secret-Key Packet (Tag 5)
//
//    A Secret-Key packet contains all the information that is found in a
//    Public-Key packet, including the public-key material, but also
//    includes the secret-key material after all the public-key fields.
  packetBody.append(publicKeyPacket.body);

  // 3.7.2.1.  Secret-Key Encryption
  //
  //    An S2K specifier can be stored in the secret keyring to specify how
  //    to convert the passphrase to a key that unlocks the secret data.
  //    Older versions of PGP just stored a cipher algorithm octet preceding
  //    the secret data or a zero to indicate that the secret data was
  //    unencrypted.  The MD5 hash function was always used to convert the
  //    passphrase to a key for the specified cipher algorithm.
  //
  //    For compatibility, when an S2K specifier is used, the special value
  //    254 or 255 is stored in the position where the hash algorithm octet
  //    would have been in the old data structure.  This is then followed
  //    immediately by a one-octet algorithm identifier, and then by the S2K
  //    specifier as encoded above.
  //
  //    Therefore, preceding the secret data there will be one of these
  //    possibilities:
  //
  //   0:           secret data is unencrypted (no passphrase)
  packetBody.writeByte(SECRET_KEY_ENCRYPTION_OFF);

  // Append the actual secret key material, in MPI format as specified above
  const ByteBuffer keyWrappedInMpiFormat = wrapKeyAsMpiFormat(secretKey);
  packetBody.append(keyWrappedInMpiFormat);
  packetBody.write16Bits(calculateCheckSumOfWrappedSecretKey(keyWrappedInMpiFormat));
  return packetBody;
}

EdDsaSecretKeyPacket::EdDsaSecretKeyPacket(
  const EdDsaPublicPacket& publicKeyPacket,
  const ByteBuffer& _secretKey,
  uint32_t _timestamp
) : OpenPgpPacket(PTAG_SECRET),
  secretKey(_secretKey),
  timestamp(_timestamp),
  body(createEd25519EdDsaSecretKeyPacketBody(secretKey, publicKeyPacket, timestamp))
  {}

const ByteBuffer& EdDsaSecretKeyPacket::getBody() const { return body; };
