/**
 * @file pqc_config.hpp
 * @brief Post-Quantum Cryptography configuration and feature flags
 *
 * This file defines compile-time configuration for PQC features in Nocturne-KX.
 *
 * NIST Standards Implemented:
 * - FIPS 203 (ML-KEM): Module-Lattice-Based Key-Encapsulation Mechanism
 * - FIPS 204 (ML-DSA): Module-Lattice-Based Digital Signature Algorithm
 * - FIPS 205 (SLH-DSA): Stateless Hash-Based Digital Signature Algorithm
 *
 * @version 4.0.0
 * @date 2025-11-27
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

// ============================================================================
// FEATURE FLAGS
// ============================================================================

/**
 * @brief Enable Post-Quantum Cryptography support
 *
 * When enabled, Nocturne-KX will compile with liboqs and support PQC algorithms.
 * This flag is automatically set by CMake when ENABLE_PQC=ON.
 */
#ifndef NOCTURNE_ENABLE_PQC
#define NOCTURNE_ENABLE_PQC 1
#endif

/**
 * @brief Default KEM algorithm type
 *
 * Options:
 * - 0: CLASSIC_X25519 (no PQC, fallback mode)
 * - 1: HYBRID_X25519_MLKEM1024 (recommended, defense-in-depth)
 * - 2: PURE_MLKEM1024 (future mode, when PQC is fully proven)
 */
#ifndef NOCTURNE_DEFAULT_KEM_TYPE
#define NOCTURNE_DEFAULT_KEM_TYPE 1  // Hybrid by default
#endif

/**
 * @brief Default signature algorithm type
 *
 * Options:
 * - 0: CLASSIC_ED25519 (no PQC, fallback mode)
 * - 1: HYBRID_ED25519_MLDSA87 (recommended)
 * - 2: CONSERVATIVE_SLHDSA (hash-based, slowest but most conservative)
 */
#ifndef NOCTURNE_DEFAULT_SIG_TYPE
#define NOCTURNE_DEFAULT_SIG_TYPE 1  // Hybrid by default
#endif

/**
 * @brief Enable algorithm agility (runtime switching)
 *
 * When enabled, allows negotiating different PQC algorithms at runtime.
 * Increases binary size but provides maximum flexibility.
 */
#ifndef NOCTURNE_ENABLE_ALGORITHM_AGILITY
#define NOCTURNE_ENABLE_ALGORITHM_AGILITY 1
#endif

/**
 * @brief Enable backward compatibility with v3.x (non-PQC)
 *
 * When enabled, Nocturne-KX v4.0 can still communicate with v3.x peers
 * that don't support PQC. New sessions will use PQC if both sides support it.
 */
#ifndef NOCTURNE_ENABLE_BACKWARD_COMPAT
#define NOCTURNE_ENABLE_BACKWARD_COMPAT 1
#endif

// ============================================================================
// PERFORMANCE TUNING
// ============================================================================

/**
 * @brief Use AVX2-optimized implementations when available
 *
 * liboqs provides AVX2-optimized versions of PQC algorithms.
 * Significantly faster on x86-64 CPUs with AVX2 support.
 */
#ifndef NOCTURNE_USE_AVX2
#if defined(__AVX2__) || defined(_M_X64)
#define NOCTURNE_USE_AVX2 1
#else
#define NOCTURNE_USE_AVX2 0
#endif
#endif

/**
 * @brief Enable side-channel protection in PQC operations
 *
 * Applies constant-time operations, cache flushing, and random delays
 * to PQC key generation, encapsulation, and signing.
 */
#ifndef NOCTURNE_PQC_SIDE_CHANNEL_PROTECTION
#define NOCTURNE_PQC_SIDE_CHANNEL_PROTECTION 1
#endif

// ============================================================================
// TESTING AND DEBUGGING
// ============================================================================

/**
 * @brief Enable PQC algorithm test vectors
 *
 * When enabled, compile NIST Known Answer Tests (KAT) for validation.
 * Disable in production to reduce binary size.
 */
#ifndef NOCTURNE_ENABLE_PQC_KAT
#ifdef NDEBUG
#define NOCTURNE_ENABLE_PQC_KAT 0  // Disabled in release builds
#else
#define NOCTURNE_ENABLE_PQC_KAT 1  // Enabled in debug builds
#endif
#endif

/**
 * @brief Enable detailed PQC logging
 *
 * Logs all PQC operations (keygen, encaps, decaps, sign, verify)
 * to audit trail. Useful for debugging but verbose.
 */
#ifndef NOCTURNE_PQC_VERBOSE_LOGGING
#define NOCTURNE_PQC_VERBOSE_LOGGING 0
#endif

// ============================================================================
// MIGRATION STRATEGY
// ============================================================================

/**
 * @brief Gradual PQC rollout percentage
 *
 * Controls what percentage of new sessions use PQC.
 * - 0: Disabled (classic crypto only)
 * - 50: 50% of sessions use PQC (A/B testing)
 * - 100: All sessions use PQC (full deployment)
 *
 * Useful for gradual rollout to production.
 */
#ifndef NOCTURNE_PQC_ROLLOUT_PERCENTAGE
#define NOCTURNE_PQC_ROLLOUT_PERCENTAGE 100  // Full deployment by default
#endif

/**
 * @brief Allow fallback to classic crypto if PQC fails
 *
 * If PQC operation fails (e.g., memory allocation, corrupted key),
 * attempt to fall back to classic X25519/Ed25519.
 *
 * WARNING: Disabling this improves security but may cause compatibility issues.
 */
#ifndef NOCTURNE_ALLOW_PQC_FALLBACK
#define NOCTURNE_ALLOW_PQC_FALLBACK 1
#endif

// ============================================================================
// NAMESPACE
// ============================================================================

namespace nocturne {
namespace pqc {

// ----------------------------------------------------------------------------
// Compile-time constants (P6.2: typed inline constexpr, not macros — they
// participate in overload resolution, respect namespaces, and show up in
// the debugger; only the #ifndef-guarded build toggles above stay macros
// because they are legitimately overridable from the compiler command line).
// ----------------------------------------------------------------------------

/// Nocturne-KX release version with PQC support.
inline constexpr int              VERSION_MAJOR  = 4;
inline constexpr int              VERSION_MINOR  = 0;
inline constexpr int              VERSION_PATCH  = 0;
inline constexpr std::string_view VERSION_STRING = "4.0.0-pqc";

/// @brief Wire protocol version for PQC support.
///
/// Version 4: adds PQC hybrid KEM and signatures.
/// Version 3: classic crypto only (X25519 + Ed25519).
///
/// @warning Wire contract: this value is bound into the hybrid-KEM
///          combined secret on BOTH encapsulate and decapsulate (see
///          commit 9b5c00b — a divergence produces ciphertexts that pass
///          every compile check but fail AEAD auth at runtime).
inline constexpr std::uint32_t PROTOCOL_VERSION = 4;

/// @brief NIST post-quantum security level targeted by Nocturne-KX.
///
/// Level 5 ≈ AES-256 (2^298 operations) — the highest defined level.
/// ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204) are the Level-5
/// parameter sets in use.
inline constexpr int PQC_SECURITY_LEVEL = 5;

/// @brief Approximate packet overhead of the hybrid PQC components.
///
/// KEM: X25519 ephemeral PK (32 B) + ML-KEM-1024 ciphertext (1568 B).
/// Sig: Ed25519 (64 B) + ML-DSA-87 (~4627 B).
inline constexpr std::size_t HYBRID_KEM_OVERHEAD = 1600;
inline constexpr std::size_t HYBRID_SIG_OVERHEAD = 4700;

/**
 * @brief PQC configuration structure (runtime)
 *
 * Allows runtime configuration of PQC features without recompilation.
 */
struct Config {
    bool pqc_enabled = NOCTURNE_ENABLE_PQC;
    bool algorithm_agility = NOCTURNE_ENABLE_ALGORITHM_AGILITY;
    bool backward_compat = NOCTURNE_ENABLE_BACKWARD_COMPAT;
    bool side_channel_protection = NOCTURNE_PQC_SIDE_CHANNEL_PROTECTION;
    bool verbose_logging = NOCTURNE_PQC_VERBOSE_LOGGING;
    int rollout_percentage = NOCTURNE_PQC_ROLLOUT_PERCENTAGE;
    bool allow_fallback = NOCTURNE_ALLOW_PQC_FALLBACK;

    /**
     * @brief Get singleton configuration instance
     */
    static Config& instance() {
        static Config cfg;
        return cfg;
    }
};

} // namespace pqc
} // namespace nocturne
