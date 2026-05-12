/// @file file_io.hpp
/// @brief Tiny file I/O helpers shared by the CLI, ReplayDB, and key
///        material loaders.
///
/// These wrap `<fstream>` with the project's exception type so that
/// I/O failures are unambiguous and so call sites don't repeat the
/// open-then-check-then-read pattern. All three functions are scope-
/// safe: returning normally implies the operation completed
/// atomically (write_all uses truncate-and-replace via the underlying
/// ofstream).
///
/// @version 1.0.0
/// @par Thread safety
///   Each call is independent of every other; concurrent reads of the
///   same file are safe, concurrent reads/writes follow filesystem
///   semantics. The helpers themselves hold no shared state.
/// @par Exception safety
///   Strong. All three throw @ref IOError on failure and leave no
///   half-written state observable to the caller.

#pragma once

#include "byte_span.hpp"
#include "types.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace nocturne {

/// @brief Read the whole contents of @p p as a byte vector.
/// @par Pre  @p p refers to a regular file readable by the caller.
/// @par Post Returned vector has @c std::filesystem::file_size(p) bytes.
/// @par Exception safety: Throws @ref IOError when the file cannot be
///                        opened.
[[nodiscard]] Bytes read_all(const std::filesystem::path& p);

/// @brief Write @p data to @p p, truncating any existing contents.
/// @par Exception safety: Throws @ref IOError on open / write failure.
void write_all(const std::filesystem::path& p, const Bytes& data);

/// @brief Like @ref write_all but takes a raw pointer + length pair —
///        used by call sites that hold a fixed-size buffer
///        (std::array key material) and don't want to construct a
///        Bytes copy.
void write_all_raw(const std::filesystem::path& p,
                   const std::uint8_t*           data,
                   std::size_t                    n);

}  // namespace nocturne
