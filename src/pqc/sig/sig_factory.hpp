/**
 * @file sig_factory.hpp
 * @brief Factory for digital-signature scheme instances.
 *
 * Mirrors the KEMFactory pattern in src/pqc/kem/kem_factory.hpp. Returns a
 * unique_ptr<SignatureScheme> for the requested SigType, gating the PQC
 * backends behind NOCTURNE_ENABLE_PQC.
 *
 * @version 4.1.0
 */

#pragma once

#include "sig_interface.hpp"
#include <memory>

namespace nocturne {
namespace pqc {

class SignatureFactory {
public:
    /// Create a SignatureScheme instance for the requested SigType. Throws
    /// std::runtime_error when the requested type isn't compiled in.
    std::unique_ptr<SignatureScheme> create(SigType type);

    /// Cheap check — does the current build support this SigType?
    static bool is_available(SigType type);

    /// Human-readable description (also used in audit messages).
    static std::string get_description(SigType type);
};

} // namespace pqc
} // namespace nocturne
