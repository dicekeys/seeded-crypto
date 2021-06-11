#pragma once

#include "ByteBuffer.hpp"

const std::string createUserIdPacketContent(const std::string& userName, const std::string& email);
const ByteBuffer createUserPacketBody(const std::string& contentString);
const ByteBuffer createUserPacketHashPreimage(const ByteBuffer& userIdPacketBody);
const ByteBuffer createUserPacket(const ByteBuffer& userPacketBody);
const ByteBuffer createUserPacket(const std::string& userName, const std::string& email);
