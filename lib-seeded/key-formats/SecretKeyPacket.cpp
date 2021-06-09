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

const ByteBuffer createSecretPacket(const ByteBuffer &secretKey, const ByteBuffer &publicKey, uint32_t timestamp) {
  ByteBuffer packetBody;
  packetBody.writeByte(Version);
  packetBody.write32Bits(timestamp);
  packetBody.writeByte(Ed25519Algorithm);
  packetBody.writeByte(Ed25519CurveOid.size());
  packetBody.append(Ed25519CurveOid);

  packetBody.append(wrapKeyWithLengthPrefixAndTrim(taggedPublicKey(publicKey)));

  packetBody.writeByte(s2kUsage);

  const ByteBuffer wrappedSecretKey = wrapKeyWithLengthPrefixAndTrim(secretKey);
  packetBody.append(wrappedSecretKey);
  packetBody.write16Bits(calculateCheckSumOfWrappedSecretKey(wrappedSecretKey));
  return createPacket(pTagSecretPacket, packetBody);
}
