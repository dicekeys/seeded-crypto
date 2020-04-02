#pragma once

#include "sodium-initializer.hpp"
#include <sodium.h>
#include <memory.h>
#include <vector>

class SodiumBuffer {
  public:
  unsigned char* data;
  const size_t length;

  SodiumBuffer(size_t length, const unsigned char* bufferData = NULL);

  SodiumBuffer(const std::vector<unsigned char> &bufferData);

  SodiumBuffer(const SodiumBuffer &other);

  ~SodiumBuffer();

  const std::vector<unsigned char> toVector() const;
};
