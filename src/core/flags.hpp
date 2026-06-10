/// @file flags.hpp
/// @brief Packet wire flags as a strongly-typed `enum class` with full
///        bitwise-operator support, plus protocol version and field-size
///        caps.
///
/// **Why an enum class instead of `constexpr uint8_t FLAG_*`.** Raw
/// integer flags allow accidental cross-type comparisons (`if (flags ==
/// HSM_TYPE_FILE)`), silent narrowing, and no auto-completion grouping.
/// `enum class Flag` gives us:
///   - Type-checked at the call site — passing a Flag to a function
///     expecting an `int` is a compile error.
///   - All values appear under one IDE auto-completion grouping.
///   - Bitwise operators are still ergonomic because we explicitly
///     overload them below.
///
/// **Backward compatibility.** The numeric values 0x01/0x02/0x04/0x08
/// remain unchanged — they are part of the wire format. Existing call
/// sites that still spell `FLAG_HAS_SIG` keep working via the legacy
/// constexpr aliases at the bottom of this header; new code should use
/// the @ref Flag enum.
///
/// @version 1.0.0

#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace nocturne {

/// @brief Outer Nocturne packet protocol version.
///
/// Bumped only when the wire layout changes in a backward-incompatible
/// way. New optional fields are added via flag bits without a version
/// bump (deserializer rejects unknown flag bits gracefully).
inline constexpr std::uint8_t VERSION = 0x03;

/// @brief Maximum accepted KEM ciphertext size (bytes).
///
/// Hybrid X25519+ML-KEM-1024 is 1601 B; the 4 KiB cap leaves headroom
/// for future schemes (e.g., HQC) while bounding allocation-amplification
/// exposure during deserialize.
inline constexpr std::size_t MAX_PQC_KEM_CT_SIZE = 4 * 1024;

/// @brief Maximum accepted PQC signature size (bytes).
///
/// Hybrid Ed25519+ML-DSA-87 is 4691 B; the 8 KiB cap covers SLH-DSA-256
/// (~7.8 KiB) and similar post-quantum signature variants.
inline constexpr std::size_t MAX_PQC_SIG_SIZE = 8 * 1024;

/// @brief Packet flag bits.
///
/// Wire identifiers — values MUST NOT be renumbered.
///
/// | Bit  | Name      | Payload semantics                                          |
/// |------|-----------|-------------------------------------------------------------|
/// | 0x01 | HasSig    | Fixed 64-byte Ed25519 signature trails the packet.          |
/// | 0x02 | HasRatchet| 32-byte ephemeral X25519 ratchet pk after the header.       |
/// | 0x04 | HasPqcKem | [1B kem_type][4B LE len][N bytes ct] block after counter.   |
/// | 0x08 | HasPqcSig | [1B sig_type][4B LE len][N bytes sig] block before HasSig.  |
enum class Flag : std::uint8_t {
    None       = 0x00,
    HasSig     = 0x01,
    HasRatchet = 0x02,
    HasPqcKem  = 0x04,
    HasPqcSig  = 0x08,
};

// Wire contract: every flag is a single distinct bit. has_single_bit
// proves each is a power of two; the OR-sum equaling 0x0F proves no two
// flags share a bit (a collision would shrink the OR below the sum).
static_assert(std::has_single_bit(static_cast<std::uint8_t>(Flag::HasSig)) &&
              std::has_single_bit(static_cast<std::uint8_t>(Flag::HasRatchet)) &&
              std::has_single_bit(static_cast<std::uint8_t>(Flag::HasPqcKem)) &&
              std::has_single_bit(static_cast<std::uint8_t>(Flag::HasPqcSig)),
              "every Flag must be a single bit");
static_assert((static_cast<std::uint8_t>(Flag::HasSig) |
               static_cast<std::uint8_t>(Flag::HasRatchet) |
               static_cast<std::uint8_t>(Flag::HasPqcKem) |
               static_cast<std::uint8_t>(Flag::HasPqcSig)) == 0x0F,
              "Flag bits must be distinct (wire values are frozen)");

// -----------------------------------------------------------------------
// Bitwise operators
// -----------------------------------------------------------------------
// Define manually rather than via a generic `enable_bitmask` template
// because that machinery requires ADL gymnastics and we only need it
// for this one enum. All operators are constexpr + noexcept.
// -----------------------------------------------------------------------

[[nodiscard]] constexpr Flag operator|(Flag a, Flag b) noexcept {
    using U = std::underlying_type_t<Flag>;
    return static_cast<Flag>(static_cast<U>(a) | static_cast<U>(b));
}
[[nodiscard]] constexpr Flag operator&(Flag a, Flag b) noexcept {
    using U = std::underlying_type_t<Flag>;
    return static_cast<Flag>(static_cast<U>(a) & static_cast<U>(b));
}
[[nodiscard]] constexpr Flag operator^(Flag a, Flag b) noexcept {
    using U = std::underlying_type_t<Flag>;
    return static_cast<Flag>(static_cast<U>(a) ^ static_cast<U>(b));
}
[[nodiscard]] constexpr Flag operator~(Flag a) noexcept {
    using U = std::underlying_type_t<Flag>;
    return static_cast<Flag>(~static_cast<U>(a));
}
constexpr Flag& operator|=(Flag& a, Flag b) noexcept { a = a | b; return a; }
constexpr Flag& operator&=(Flag& a, Flag b) noexcept { a = a & b; return a; }
constexpr Flag& operator^=(Flag& a, Flag b) noexcept { a = a ^ b; return a; }

/// @brief Test whether any of @p bits is set in @p f.
///
/// Common idiom replaces `(f & Flag::HasSig) != Flag::None` with the
/// more readable `has_any(f, Flag::HasSig)`.
///
/// @par Thread safety: Lock-free, pure.
/// @par Exception safety: noexcept.
[[nodiscard]] constexpr bool has_any(Flag f, Flag bits) noexcept {
    return (f & bits) != Flag::None;
}

/// @brief Test whether *all* @p bits are set in @p f.
[[nodiscard]] constexpr bool has_all(Flag f, Flag bits) noexcept {
    return (f & bits) == bits;
}

/// @brief Underlying-type cast for wire serialization.
[[nodiscard]] constexpr std::uint8_t to_underlying(Flag f) noexcept {
    return static_cast<std::uint8_t>(f);
}

/// @brief Build a Flag from its wire byte. No validation — unknown bits
///        are preserved verbatim; the deserializer is responsible for
///        rejecting bits it doesn't recognize.
[[nodiscard]] constexpr Flag flag_from_byte(std::uint8_t b) noexcept {
    return static_cast<Flag>(b);
}

// -----------------------------------------------------------------------
// Legacy numeric aliases
// -----------------------------------------------------------------------
// Existing call sites in nocturne-kx.cpp still spell FLAG_HAS_SIG /
// FLAG_HAS_RATCHET / FLAG_HAS_PQC_KEM / FLAG_HAS_PQC_SIG. These aliases
// keep them compiling unchanged. New code should use the @ref Flag enum
// directly. Aliases will be removed in P5.9 once all call sites
// migrate.
// -----------------------------------------------------------------------

inline constexpr std::uint8_t FLAG_HAS_SIG     = to_underlying(Flag::HasSig);
inline constexpr std::uint8_t FLAG_HAS_RATCHET = to_underlying(Flag::HasRatchet);
inline constexpr std::uint8_t FLAG_HAS_PQC_KEM = to_underlying(Flag::HasPqcKem);
inline constexpr std::uint8_t FLAG_HAS_PQC_SIG = to_underlying(Flag::HasPqcSig);

}  // namespace nocturne
