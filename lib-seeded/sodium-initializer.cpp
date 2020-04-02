#include <sodium.h>
#include <exception>
#include <stdexcept>
#include "sodium-initializer.hpp"

void ensureSodiumInitialized() {
  static bool hasInitializedSodium = false;
  if (!hasInitializedSodium) {
    if (sodium_init() < 0) {
      throw std::invalid_argument("Could not initialize sodium");
      /* panic! the library couldn't be initialized, it is not safe to use */
    }
    hasInitializedSodium = true;
  }
}
