#include "UserPacket.hpp"
#include "Packet.hpp"

const ByteBuffer createUserPacketBody(const std::string& userName, const std::string& email) {
  // FIXME -- encoding or validation needed?
  std::string userNameAndEmail = userName + " <" + email + ">";
  std::vector<uint8_t> userNameAndEmailByteVector(userNameAndEmail.begin(), userNameAndEmail.end());
  return ByteBuffer(userNameAndEmailByteVector);
}

const ByteBuffer createUserPacketHashPreimage(const ByteBuffer& userIdPacketBody) {
  ByteBuffer preimage;
  preimage.writeByte(pTagUserIdPacket);
  preimage.write32Bits(userIdPacketBody.size());
  preimage.append(userIdPacketBody);
  return preimage;
}

const ByteBuffer createUserPacket(const ByteBuffer& userPacketBody) {
  return createPacket(pTagUserIdPacket, userPacketBody);
}

const ByteBuffer createUserPacket(const std::string &userName, const std::string &email) {
    return createUserPacket(createUserPacketBody(userName, email));
}