#include "Packet.hpp"
#include "SecretKeyPacket.hpp"
#include "PublicKeyPacket.hpp"

const uint16_t calculateCheckSumOfWrappedSecretKey(const ByteBuffer &wrappedSecretKey) {
  uint16_t checksum = 0;
  for (size_t i = 0; i < wrappedSecretKey.byteVector.size(); i ++) {
    const uint8_t byte = wrappedSecretKey.byteVector[i];
    checksum += byte;
  }
  return checksum;
}

const ByteBuffer createEd25519SecretKeyPacketBody(const ByteBuffer& secretKey, const ByteBuffer& publicKey, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(ALGORITHM_ED_DSA);
  packetBody.writeByte(ALGORITHM_ED_DSA_CURVE_OID_25519.size());
  packetBody.append(ALGORITHM_ED_DSA_CURVE_OID_25519);

  packetBody.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKey)));

  packetBody.writeByte(s2kUsage);

  const ByteBuffer wrappedSecretKey = wrapKeyWithLengthPrefixAndTrim(secretKey);
  packetBody.append(wrappedSecretKey);
  packetBody.write16Bits(calculateCheckSumOfWrappedSecretKey(wrappedSecretKey));
  return packetBody;
}

const ByteBuffer createEd25519SecretKeyPacket(const ByteBuffer &packetBody) {
  return createOpenPgpPacket(pTagSecretPacket, packetBody);
}

const ByteBuffer createEd25519SecretKeyPacket(const ByteBuffer& secretKey, const ByteBuffer& publicKey, uint32_t timestamp) {
  return createEd25519SecretKeyPacket(createEd25519SecretKeyPacketBody(secretKey, publicKey, timestamp));
}

const ByteBuffer createEd25519SecretKeyPacket(
  const SigningKey& signingKey,
  uint32_t timestamp
) {
  return createEd25519SecretKeyPacket(ByteBuffer(signingKey.getSeedBytes()), ByteBuffer(signingKey.getSignatureVerificationKeyBytes()), timestamp);
}
