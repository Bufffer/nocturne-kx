/// @file test_error_result.cpp
/// @brief Smoke tests for the P5.0 foundation headers: error.hpp,
///        result.hpp, byte_span.hpp.
///
/// These tests are intentionally narrow. They exist to (a) force CI
/// compilation of the new headers across every push, (b) document the
/// intended usage of @c Result<T> / @c Error / @c BytesView in one
/// place, and (c) catch any libstdc++/libc++ regression that breaks
/// the @c std::expected pipeline on the runner image.
///
/// @par CI tag: `[foundation]` — gated by a must-pass step.

#include <catch2/catch_test_macros.hpp>

#include "../../src/core/error.hpp"
#include "../../src/core/result.hpp"
#include "../../src/core/byte_span.hpp"
#include "../../src/core/flags.hpp"
#include "../../src/core/types.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using nocturne::Bytes;
using nocturne::BytesView;
using nocturne::Ed25519KeyPair;
using nocturne::Error;
using nocturne::ErrorCode;
using nocturne::Flag;
using nocturne::HSMError;
using nocturne::MutableBytesView;
using nocturne::NocturneError;
using nocturne::Result;
using nocturne::Status;
using nocturne::X25519KeyPair;
using nocturne::as_mut_view;
using nocturne::as_view;
using nocturne::category;
using nocturne::err;
using nocturne::flag_from_byte;
using nocturne::has_all;
using nocturne::has_any;
using nocturne::ok;
using nocturne::to_string_view;
using nocturne::to_underlying;

TEST_CASE("ErrorCode names are stable and complete", "[foundation]") {
    // Sample one entry per category to catch any switch fall-through.
    REQUIRE(to_string_view(ErrorCode::Ok) == "Ok");
    REQUIRE(to_string_view(ErrorCode::AeadAuthFailed) == "AeadAuthFailed");
    REQUIRE(to_string_view(ErrorCode::PacketTruncated) == "PacketTruncated");
    REQUIRE(to_string_view(ErrorCode::SignatureVerifyFailed) == "SignatureVerifyFailed");
    REQUIRE(to_string_view(ErrorCode::KemDecapsulateFailed) == "KemDecapsulateFailed");
    REQUIRE(to_string_view(ErrorCode::ReplayDetected) == "ReplayDetected");
    REQUIRE(to_string_view(ErrorCode::RotationStale) == "RotationStale");
    REQUIRE(to_string_view(ErrorCode::RateLimited) == "RateLimited");
    REQUIRE(to_string_view(ErrorCode::AuditChainBroken) == "AuditChainBroken");
    REQUIRE(to_string_view(ErrorCode::HsmUnhealthy) == "HsmUnhealthy");
    REQUIRE(to_string_view(ErrorCode::SodiumInit) == "SodiumInit");
}

TEST_CASE("ErrorCode category bucketing", "[foundation]") {
    REQUIRE(category(ErrorCode::AeadAuthFailed)       == 1);
    REQUIRE(category(ErrorCode::PacketTruncated)      == 2);
    REQUIRE(category(ErrorCode::SignatureVerifyFailed)== 3);
    REQUIRE(category(ErrorCode::KemDecapsulateFailed) == 4);
    REQUIRE(category(ErrorCode::ReplayDetected)       == 5);
    REQUIRE(category(ErrorCode::RotationStale)        == 6);
    REQUIRE(category(ErrorCode::RateLimited)          == 7);
    REQUIRE(category(ErrorCode::AuditChainBroken)     == 8);
    REQUIRE(category(ErrorCode::HsmUnhealthy)         == 9);
    REQUIRE(category(ErrorCode::IoFailed)             == 10);
}

TEST_CASE("Error captures message and source location", "[foundation]") {
    auto build_err = []() -> Error {
        return Error{ErrorCode::ReplayDetected, "counter regressed"};
    };
    auto e = build_err();
    REQUIRE(e.code == ErrorCode::ReplayDetected);
    REQUIRE(e.message == "counter regressed");
    REQUIRE(e.name() == "ReplayDetected");
    REQUIRE(e.domain() == 5);
    // The source location was captured at the call site of build_err's
    // return statement — file ends with "test_error_result.cpp".
    std::string_view file{e.where.file_name()};
    REQUIRE(file.find("test_error_result.cpp") != std::string_view::npos);
}

TEST_CASE("Result<T> happy path", "[foundation]") {
    auto succeed = [](int x) -> Result<int> { return x + 1; };
    auto r = succeed(41);
    REQUIRE(r.has_value());
    REQUIRE(*r == 42);
}

TEST_CASE("Result<T> error path via err()", "[foundation]") {
    auto fail = []() -> Result<int> {
        return err(ErrorCode::SignatureVerifyFailed, "bad sig");
    };
    auto r = fail();
    REQUIRE_FALSE(r.has_value());
    REQUIRE(r.error().code == ErrorCode::SignatureVerifyFailed);
    REQUIRE(r.error().message == "bad sig");
}

TEST_CASE("Result<T> monadic and_then composition", "[foundation]") {
    auto parse  = [](int n) -> Result<int> {
        if (n < 0) return err(ErrorCode::PacketTruncated, "negative");
        return n;
    };
    auto square = [](int n) -> Result<int> { return n * n; };
    auto check  = [](int n) -> Result<int> {
        if (n > 100) return err(ErrorCode::PacketFieldOversized, "too big");
        return n;
    };

    SECTION("all pass") {
        auto r = parse(5).and_then(square).and_then(check);
        REQUIRE(r.has_value());
        REQUIRE(*r == 25);
    }
    SECTION("first stage fails — short-circuits") {
        auto r = parse(-1).and_then(square).and_then(check);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketTruncated);
    }
    SECTION("last stage fails") {
        auto r = parse(20).and_then(square).and_then(check);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketFieldOversized);
    }
}

TEST_CASE("Status (Result<void>) round-trip", "[foundation]") {
    auto good = []() -> Status { return ok(); };
    auto bad  = []() -> Status {
        return err(ErrorCode::RateLimited, "burst exceeded");
    };
    REQUIRE(good().has_value());
    REQUIRE_FALSE(bad().has_value());
    REQUIRE(bad().error().code == ErrorCode::RateLimited);
}

// Compile-time proof of the ByteRange concept's accept/reject set.
static_assert(nocturne::ByteRange<nocturne::Bytes>);
static_assert(nocturne::ByteRange<std::array<std::uint8_t, 4>>);
static_assert(nocturne::ByteRange<nocturne::BytesView>);
static_assert(!nocturne::ByteRange<std::string>);          // char, not uint8_t
static_assert(!nocturne::ByteRange<std::vector<int>>);     // wrong element type

TEST_CASE("BytesView adapters cover container shapes", "[foundation]") {
    SECTION("from Bytes") {
        Bytes b{0x01, 0x02, 0x03};
        auto v = as_view(b);
        REQUIRE(v.size() == 3);
        REQUIRE(v[0] == 0x01);
        REQUIRE(v[2] == 0x03);
    }
    SECTION("from std::array") {
        std::array<std::uint8_t, 4> a{0xAA, 0xBB, 0xCC, 0xDD};
        auto v = as_view(a);
        REQUIRE(v.size() == 4);
        REQUIRE(v[1] == 0xBB);
    }
    SECTION("from string_view") {
        auto v = as_view(std::string_view{"abc"});
        REQUIRE(v.size() == 3);
        REQUIRE(v[0] == static_cast<std::uint8_t>('a'));
    }
}

TEST_CASE("MutableBytesView allows in-place writes", "[foundation]") {
    Bytes b(4, 0);
    auto m = as_mut_view(b);
    for (std::size_t i = 0; i < m.size(); ++i) {
        m[i] = static_cast<std::uint8_t>(i + 1);
    }
    REQUIRE(b == Bytes{0x01, 0x02, 0x03, 0x04});
}

// A canonical example of the intended monadic style used downstream in
// P5.6 / P5.8: parse → validate → process. Compile-only — exercises
// transform / or_else as well as and_then.
namespace {
Result<Bytes> parse_packet(BytesView raw) {
    if (raw.size() < 2) return err(ErrorCode::PacketTruncated, "short header");
    Bytes copy(raw.begin(), raw.end());
    return copy;
}
Result<Bytes> validate(Bytes packet) {
    if (packet[0] != 0x03) return err(ErrorCode::PacketUnknownVersion, "bad version");
    return packet;
}
}  // namespace

TEST_CASE("Flag bitwise operators round-trip the wire values", "[foundation]") {
    SECTION("legacy numeric aliases preserved for backward compat") {
        REQUIRE(to_underlying(Flag::HasSig)     == 0x01);
        REQUIRE(to_underlying(Flag::HasRatchet) == 0x02);
        REQUIRE(to_underlying(Flag::HasPqcKem)  == 0x04);
        REQUIRE(to_underlying(Flag::HasPqcSig)  == 0x08);
    }

    SECTION("operator|, operator& compose multi-flag values") {
        Flag both = Flag::HasSig | Flag::HasPqcKem;
        REQUIRE(to_underlying(both) == 0x05);

        REQUIRE(has_any(both, Flag::HasSig));
        REQUIRE(has_any(both, Flag::HasPqcKem));
        REQUIRE_FALSE(has_any(both, Flag::HasRatchet));
        REQUIRE(has_all(both, Flag::HasSig | Flag::HasPqcKem));
        REQUIRE_FALSE(has_all(both, Flag::HasSig | Flag::HasRatchet));
    }

    SECTION("operator~ and operator^ clear / toggle bits") {
        Flag f = Flag::HasSig | Flag::HasPqcSig;
        f &= ~Flag::HasSig;
        REQUIRE_FALSE(has_any(f, Flag::HasSig));
        REQUIRE(has_any(f, Flag::HasPqcSig));

        f ^= Flag::HasPqcSig;
        REQUIRE(f == Flag::None);
    }

    SECTION("flag_from_byte preserves unknown bits") {
        Flag f = flag_from_byte(0xF0);  // no defined bit set in 0xF0
        REQUIRE(to_underlying(f) == 0xF0);
    }
}

TEST_CASE("Key pair structs have the libsodium-defined sizes", "[foundation]") {
    X25519KeyPair kp{};
    REQUIRE(kp.pk.size() == 32);
    REQUIRE(kp.sk.size() == 32);

    Ed25519KeyPair ed{};
    REQUIRE(ed.pk.size() == 32);
    REQUIRE(ed.sk.size() == 64);
}

TEST_CASE("Exception hierarchy: HSMError isa NocturneError", "[foundation]") {
    try {
        throw HSMError{"pkcs11 unreachable"};
    } catch (const NocturneError& e) {
        REQUIRE(std::string{e.what()} == "pkcs11 unreachable");
    } catch (...) {
        FAIL("HSMError did not propagate through NocturneError catch");
    }
}

TEST_CASE("Composed pipeline example", "[foundation]") {
    SECTION("happy") {
        Bytes raw{0x03, 0x00, 0xAA};
        auto r = parse_packet(as_view(raw)).and_then(validate);
        REQUIRE(r.has_value());
        REQUIRE(r->size() == 3);
    }
    SECTION("fails at parse") {
        Bytes raw{0x03};  // too short
        auto r = parse_packet(as_view(raw)).and_then(validate);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketTruncated);
    }
    SECTION("fails at validate") {
        Bytes raw{0x02, 0x00, 0xAA};  // wrong version
        auto r = parse_packet(as_view(raw)).and_then(validate);
        REQUIRE_FALSE(r.has_value());
        REQUIRE(r.error().code == ErrorCode::PacketUnknownVersion);
    }
}
