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

// Nocturne-KX version with PQC support
#define NOCTURNE_VERSION_MAJOR 4
#define NOCTURNE_VERSION_MINOR 0
#define NOCTURNE_VERSION_PATCH 0
#define NOCTURNE_VERSION_STRING "4.0.0-pqc"

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
// SECURITY LEVELS
// ============================================================================

/**
 * @brief NIST Post-Quantum Security Levels
 *
 * Level 1: Equivalent to AES-128, breaking requires 2^143 operations
 * Level 2: Equivalent to SHA-256 collision, 2^207 operations
 * Level 3: Equivalent to AES-192, 2^170 operations
 * Level 4: Equivalent to SHA-384 collision, 2^272 operations
 * Level 5: Equivalent to AES-256, 2^298 operations (HIGHEST)
 *
 * Nocturne-KX targets Level 5 for maximum security.
 */
#define NOCTURNE_PQC_SECURITY_LEVEL 5

// ML-KEM (Kyber) variants
#define MLKEM_512   1  // Level 1 (not used)
#define MLKEM_768   3  // Level 3 (not used)
#define MLKEM_1024  5  // Level 5 (USED)

// ML-DSA (Dilithium) variants
#define MLDSA_44   2  // Level 2 (not used)
#define MLDSA_65   3  // Level 3 (not used)
#define MLDSA_87   5  // Level 5 (USED)

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
// WIRE FORMAT CONFIGURATION
// ============================================================================

/**
 * @brief Protocol version for PQC support
 *
 * Version 4: Adds PQC hybrid KEM and signatures
 * Version 3: Classic crypto only (X25519 + Ed25519)
 */
#define NOCTURNE_PROTOCOL_VERSION 4

/**
 * @brief Maximum packet overhead for hybrid PQC
 *
 * Hybrid packets contain both classic and PQC components:
 * - X25519 ephemeral PK: 32 bytes
 * - ML-KEM-1024 ciphertext: 1,568 bytes
 * - Total KEM overhead: ~1,600 bytes
 *
 * For signatures:
 * - Ed25519 signature: 64 bytes
 * - ML-DSA-87 signature: ~4,627 bytes
 * - Total signature overhead: ~4,691 bytes
 */
#define NOCTURNE_HYBRID_KEM_OVERHEAD 1600
#define NOCTURNE_HYBRID_SIG_OVERHEAD 4700

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
