/// @file byte_span.hpp
/// @brief Byte-buffer view aliases that replace every `(uint8_t*, size_t)`
///        pair on the public API.
///
/// **Why std::span over raw ptr+len.** Two arguments must agree on the
/// caller side; with std::span the size is bound at construction and
/// can never disagree downstream. Range-for, iterators, and subspan
/// slicing all work without the caller writing pointer arithmetic.
///
/// **Why std::uint8_t (not std::byte).** All cryptographic primitives
/// in this project flow through libsodium, which accepts
/// `const unsigned char*`. Using `std::span<const std::byte>` would
/// require a `reinterpret_cast` at every libsodium boundary; using
/// `std::span<const std::uint8_t>` aligns with the existing
/// `Bytes = std::vector<std::uint8_t>` convention and lets us pass
/// `.data()` directly. If we ever migrate off libsodium, switching the
/// underlying element type is a one-line typedef change.
///
/// **Lifetime contract.** A BytesView does **not** own its storage. The
/// underlying buffer must outlive every BytesView constructed over it.
/// Never store a BytesView as a class member without a documented
/// ownership invariant — use @ref Bytes for owning storage instead.
///
/// @version 1.0.0

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace nocturne {

// -----------------------------------------------------------------------
// Owning storage
// -----------------------------------------------------------------------

/// @brief Owned byte sequence — the canonical "buffer of bytes" type.
///
/// Aliased here so call sites don't independently pick `std::vector
/// <std::uint8_t>` vs `std::vector<unsigned char>` vs ad-hoc structs.
using Bytes = std::vector<std::uint8_t>;

// -----------------------------------------------------------------------
// Non-owning views
// -----------------------------------------------------------------------

/// @brief Read-only view over a byte sequence.
///
/// Replaces every `const uint8_t* data, std::size_t len` pair in the
/// public API. Constructible from @ref Bytes, `std::array<u8, N>`,
/// `std::string_view`, or raw `(ptr, size)`. Implicit conversion from
/// contiguous ranges is permitted.
using BytesView = std::span<const std::uint8_t>;

/// @brief Writable view over a byte sequence — output buffers.
///
/// Used as the destination half of split-input/output APIs (key
/// material write-out, in-place AEAD ciphertext slot). Same lifetime
/// rules as @ref BytesView.
using MutableBytesView = std::span<std::uint8_t>;

// -----------------------------------------------------------------------
// Adapters
// -----------------------------------------------------------------------
// Free functions, not constructors, so call sites read top-to-bottom
// without nested temporaries. All noexcept and constexpr-safe where
// the source container's data() is.
// -----------------------------------------------------------------------

/// @brief View over an owned Bytes buffer.
/// @par Thread safety: Bound by the caller's synchronization of @p v.
/// @par Exception safety: noexcept.
[[nodiscard]] inline BytesView as_view(const Bytes& v) noexcept {
    return BytesView{v.data(), v.size()};
}

/// @brief View over a fixed-size byte array. The static extent is
///        intentionally erased — the API uses dynamic-extent spans so
///        function signatures don't proliferate per array size.
template <std::size_t N>
[[nodiscard]] inline BytesView as_view(const std::array<std::uint8_t, N>& a) noexcept {
    return BytesView{a.data(), N};
}

/// @brief View over a `std::string_view`. Reinterprets char→uint8_t
///        with one well-defined cast; safe under [basic.lval] /
///        [basic.types] for trivially copyable types.
[[nodiscard]] inline BytesView as_view(std::string_view s) noexcept {
    return BytesView{
        reinterpret_cast<const std::uint8_t*>(s.data()),
        s.size()};
}

/// @brief View over a C-string literal (excludes the trailing NUL).
[[nodiscard]] inline BytesView as_view_cstr(const char* s) noexcept {
    return as_view(std::string_view{s});
}

/// @brief Mutable view over an owned Bytes buffer.
[[nodiscard]] inline MutableBytesView as_mut_view(Bytes& v) noexcept {
    return MutableBytesView{v.data(), v.size()};
}

/// @brief Mutable view over a fixed-size byte array.
template <std::size_t N>
[[nodiscard]] inline MutableBytesView as_mut_view(std::array<std::uint8_t, N>& a) noexcept {
    return MutableBytesView{a.data(), N};
}

}  // namespace nocturne
