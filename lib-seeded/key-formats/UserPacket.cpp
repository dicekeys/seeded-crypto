#include "UserPacket.hpp"
#include "Packet.hpp"

const std::string createUserIdPacketContent(const std::string& userName, const std::string& email) {
  return userName + " <" + email + ">";
}

const ByteBuffer createUserPacketBody(const std::string& contentString) {
  return ByteBuffer(std::vector<uint8_t>(contentString.begin(), contentString.end()));
}

const ByteBuffer createUserPacketHashPreimage(const ByteBuffer& userIdPacketBody) {
  ByteBuffer preimage;
  preimage.writeByte(pTagUserIdPacket);
  preimage.write32Bits(userIdPacketBody.size());
  preimage.append(userIdPacketBody);
  return preimage;
}

const ByteBuffer createUserPacket(const ByteBuffer& userPacketBody) {
  return createOpenPgpPacket(pTagUserIdPacket, userPacketBody);
}

const ByteBuffer createUserPacket(const std::string &userName, const std::string &email) {
    return createUserPacket(createUserPacketBody(createUserIdPacketContent(userName, email)));
}