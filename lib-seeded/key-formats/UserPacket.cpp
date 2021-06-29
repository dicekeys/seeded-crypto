#include "UserPacket.hpp"
#include "OpenPgpPacket.hpp"

const std::string createUserIdPacketContent(const std::string& userName, const std::string& email) {
  return userName + " <" + email + ">";
}

const ByteBuffer UserPacket::getPreImage() const {
  ByteBuffer preImage;
  preImage.writeByte(packetTag);
  preImage.write32Bits(body.size());
  preImage.append(body);
  return preImage;
};

const ByteBuffer& UserPacket::getBody() const { return body; };

UserPacket::UserPacket(const std::string& contentString) :
  OpenPgpPacket(PTAG_USER_ID),
  body(contentString)
  {}

UserPacket::UserPacket(const std::string& userName, const std::string& email) :
  OpenPgpPacket(PTAG_USER_ID),
  body(createUserIdPacketContent(userName, email))
{}