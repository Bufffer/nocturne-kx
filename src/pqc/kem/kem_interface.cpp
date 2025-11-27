/**
 * @file kem_interface.cpp
 * @brief Implementation of KEM interface utilities
 */

#include "kem_interface.hpp"
#include "../../core/side_channel.hpp"
#include <sodium.h>

namespace nocturne {
namespace pqc {

// KEMKeyPair destructor - securely wipe secret key
KEMKeyPair::~KEMKeyPair() {
    if (!secret_key.empty()) {
        side_channel_protection::secure_zero_memory(
            secret_key.data(), secret_key.size());
    }
}

// KEMSharedSecret destructor - securely wipe shared secret
KEMSharedSecret::~KEMSharedSecret() {
    side_channel_protection::secure_zero_memory(
        secret.data(), secret.size());
}

} // namespace pqc
} // namespace nocturne
