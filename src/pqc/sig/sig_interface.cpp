/**
 * @file sig_interface.cpp
 * @brief Implementation of signature interface utilities (destructors).
 */

#include "sig_interface.hpp"
#include "../../core/side_channel.hpp"

namespace nocturne {
namespace pqc {

SigKeyPair::~SigKeyPair() {
    if (!secret_key.empty()) {
        side_channel::secure_zero_memory(secret_key.data(), secret_key.size());
    }
}

} // namespace pqc
} // namespace nocturne
