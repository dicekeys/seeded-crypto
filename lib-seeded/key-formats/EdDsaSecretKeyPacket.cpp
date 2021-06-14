#include "OpenPgpPacket.hpp"
#include "EdDsaSecretKeyPacket.hpp"

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey) {
  uint16_t checksum = 0;
  for (size_t i = 0; i < wrappedSecretKey.byteVector.size(); i ++) {
    const uint8_t byte = wrappedSecretKey.byteVector[i];
    checksum += byte;
  }
  return checksum;
}

const ByteBuffer createEd25519EdDsaSecretKeyPacketBody(const ByteBuffer& secretKey, const EdDsaPublicPacket& publicKeyPacket, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(ALGORITHM_ED_DSA);
  packetBody.writeByte(ALGORITHM_ED_DSA_CURVE_OID_25519.size());
  packetBody.append(ALGORITHM_ED_DSA_CURVE_OID_25519);

  packetBody.append(wrapKeyWithLengthPrefixAndTrim(publicKeyPacket.publicKeyInEdDsaPointFormat));

  packetBody.writeByte(s2kUsage);

  const ByteBuffer wrappedSecretKey = wrapKeyWithLengthPrefixAndTrim(secretKey);
  packetBody.append(wrappedSecretKey);
  packetBody.write16Bits(calculateCheckSumOfWrappedSecretKey(wrappedSecretKey));
  return packetBody;
}

const ByteBuffer createEd25519EdDsaSecretKeyPacket(const ByteBuffer &packetBody) {
  return createOpenPgpPacket(pTagSecretPacket, packetBody);
}

const ByteBuffer createEd25519EdDsaSecretKeyPacket(const ByteBuffer& secretKey, const EdDsaPublicPacket& publicKeyPacket, uint32_t timestamp) {
  return createEd25519EdDsaSecretKeyPacket(createEd25519EdDsaSecretKeyPacketBody(secretKey, publicKeyPacket, timestamp));
}

const ByteBuffer createEd25519EdDsaSecretKeyPacket(
  const SigningKey& signingKey,
  uint32_t timestamp
) {
  const EdDsaPublicPacket publicPacket(ByteBuffer(signingKey.getSignatureVerificationKeyBytes()), timestamp);
  return createEd25519EdDsaSecretKeyPacket(ByteBuffer(signingKey.getSeedBytes()), publicPacket, timestamp);
}

EdDsaSecretKeyPacket::EdDsaSecretKeyPacket(
  const EdDsaPublicPacket& publicKeyPacket,
  const ByteBuffer& _secretKey,
  uint32_t _timestamp
) : OpenPgpPacket(pTagSecretPacket),
  secretKey(_secretKey),
  timestamp(_timestamp),
  body(createEd25519EdDsaSecretKeyPacketBody(secretKey, publicKeyPacket, timestamp))
  {}

const ByteBuffer& EdDsaSecretKeyPacket::getBody() const { return body; };
