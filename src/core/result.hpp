/// @file result.hpp
/// @brief `Result<T> = std::expected<T, Error>` plumbing for the
///        Nocturne-KX error-handling contract.
///
/// **When to return Result<T> vs throw.**
///
///   - **Result<T>** — every *recoverable* failure: signature verification
///     failed, replay detected, rotation_id stale, AEAD auth failed,
///     size mismatch, KEM/sig type unknown, audit chain broken. These
///     are *expected* outcomes for adversarial or malformed input; the
///     caller must handle them and unwinding the stack for each one is
///     pure overhead.
///
///   - **throw** — *system fault*: `sodium_init()` failure, std::bad_alloc,
///     missing file at I/O time, programmer error (precondition violated).
///     The caller has no recovery strategy and unwinding to a top-level
///     handler that exits the process is the correct action.
///
/// **Composition.** Prefer the monadic combinators of `std::expected`
/// over manual `if (!r) return r.error();` ladders:
///
/// @code
///   Result<Bytes> decrypt(BytesView packet) {
///       return parse(packet)
///           .and_then(check_replay)
///           .and_then(verify_signature)
///           .and_then(aead_decrypt);
///   }
/// @endcode
///
/// This keeps the happy path linear, errors short-circuit, and the
/// compiler can inline aggressively because no exception edges exist.
///
/// @version 1.0.0

#pragma once

#include "error.hpp"

#include <expected>
#include <source_location>
#include <string>
#include <utility>

namespace nocturne {

/// @brief Result alias.
///
/// `Result<T>::has_value()` returns true on success; otherwise
/// `error()` yields the @ref Error payload. Use `value_or(...)`,
/// `and_then(...)`, `or_else(...)`, `transform(...)`,
/// `transform_error(...)` for composition.
///
/// @tparam T Payload type on success. Use @ref Status for void.
template <typename T>
using Result = std::expected<T, Error>;

/// @brief Result alias for operations whose payload is "success only".
///
/// Equivalent to `Result<void>`. Useful for setters, validators, side-
/// effecting operations where the caller just wants to know whether
/// the work succeeded.
using Status = std::expected<void, Error>;

/// @brief Construct a failed Result concisely.
///
/// Equivalent to `std::unexpected<Error>{Error{c, std::move(m), loc}}`
/// but lets call sites write `return err(ErrorCode::ReplayDetected,
/// "counter ≤ last")` without naming `Error` or `std::unexpected`.
///
/// @par Thread safety: Lock-free, pure.
/// @par Exception safety: noexcept(false) — only because the
///      `std::string` move constructor is noexcept under the C++23 SSO
///      guarantee but the unexpected constructor isn't formally
///      noexcept. In practice no throw occurs unless allocator fails.
[[nodiscard]] inline std::unexpected<Error> err(
    ErrorCode            code,
    std::string          message = {},
    std::source_location loc     = std::source_location::current())
{
    return std::unexpected<Error>{Error{code, std::move(message), loc}};
}

/// @brief Construct a successful Status (Result<void>).
///
/// Spelled `ok()` for symmetry with `err(...)`. Equivalent to `Status{}`.
[[nodiscard]] inline Status ok() noexcept { return Status{}; }

}  // namespace nocturne
