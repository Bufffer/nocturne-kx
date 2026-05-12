/// @file audit_logger.hpp
/// @brief In-process audit logger with BLAKE2b hash chaining, optional
///        Ed25519 signing per record, optional WORM directory mirror,
///        and a verify_chain() free function that re-checks integrity
///        from a JSONL file.
///
/// **Scope.** This is the *inline* audit logger the CLI consumes when
/// `--audit-log <path>` is supplied. It is distinct from the enterprise
/// nocturne::security::AuditLogger (src/security/audit_logger.hpp) which
/// has a richer schema (sequence number, action/object/result fields,
/// ISO-8601 timestamps). The two have separate verify_chain
/// implementations because the canonical-bytes encodings differ —
/// changing one without the other breaks integrity verification.
///
/// **Wire/log format.** Each line is a single JSON object:
///
/// @code
///   {"ts":<u64 ms since epoch>,
///    "sev":"INFO"|"WARN"|"ERROR"|"SECURITY",
///    "cat":"<category>",
///    "sub":"<subject>",
///    "msg":"<message — only " is escaped as \">",
///    "prev":"<64-char hex prev_hash>",
///    "hash":"<64-char hex this record's hash>",
///    "sig":"<128-char hex Ed25519 sig over hash>"  // optional
///    "pub":"<64-char hex signer pk>"                // optional
///   }
/// @endcode
///
/// **Hash chain**: `hash[N] = BLAKE2b-256(prev[N] || u64_le(ts) || u8(sev)
/// || 0 || cat || 0 || sub || 0 || msg)`. The first record's `prev` is
/// 32 zero bytes. Tampering with any record breaks the chain at that
/// line; verify_chain reports the line number.
///
/// @par Thread safety
///   AuditLogger::log is protected by an internal mutex; concurrent
///   loggers on the same instance are serialised. Construction is not
///   thread-safe — instantiate from a single thread before sharing.
///   The free helpers (verify_chain, blake2b_32, sev_from_str, ...) are
///   pure functions and safe to call concurrently.
/// @par Exception safety
///   Per-record I/O failures and WORM write errors are swallowed
///   best-effort; the call still returns. Hashing failure throws
///   std::runtime_error (libsodium cannot legitimately fail here).
///
/// @version 1.0.0

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <sodium.h>

namespace audit_log {

/// @brief Audit record severity. Wire values part of the schema —
///        DO NOT renumber.
enum class Severity { INFO, WARN, ERROR, SECURITY };

/// @brief 32-byte BLAKE2b hash output — the chain element type.
using Hash32 = std::array<std::uint8_t, 32>;

/// @brief BLAKE2b-256 over @p data, no key.
/// @par Exception safety: Strong. Throws std::runtime_error on
///                        libsodium failure (should never happen).
[[nodiscard]] inline Hash32 blake2b_32(const std::vector<std::uint8_t>& data) {
    Hash32 out{};
    if (crypto_generichash(out.data(), out.size(),
                           data.data(), data.size(),
                           nullptr, 0) != 0) {
        throw std::runtime_error{"audit: hash failed"};
    }
    return out;
}

/// @brief Hex-encode @p n bytes from @p p (lowercase).
[[nodiscard]] inline std::string hex_from(const std::uint8_t* p, std::size_t n) {
    static constexpr const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        const unsigned v = p[i];
        s.push_back(kHex[v >> 4]);
        s.push_back(kHex[v & 0xF]);
    }
    return s;
}
/// @brief Hex-encode a Hash32.
[[nodiscard]] inline std::string hex_from(const Hash32& h) {
    return hex_from(h.data(), h.size());
}

// -----------------------------------------------------------------------
// AuditLogger
// -----------------------------------------------------------------------

class AuditLogger {
  public:
    /// @brief Construct an audit logger.
    /// @param path        JSONL output file. nullopt disables logging.
    /// @param key_path    Raw Ed25519 64-byte secret-key file for
    ///                    per-record signing. nullopt → unsigned log.
    /// @param anchor_file File whose contents are hashed and appended
    ///                    as the chain's anchor record on startup
    ///                    (typically an RFC 3161 TSA token). nullopt →
    ///                    no anchor.
    /// @param worm_dir    Append-only directory; each record is also
    ///                    written as a per-file copy with owner-write
    ///                    bit cleared. nullopt → no WORM mirror.
    explicit AuditLogger(const std::optional<std::filesystem::path>& path,
                         const std::optional<std::filesystem::path>& key_path,
                         const std::optional<std::filesystem::path>& anchor_file,
                         const std::optional<std::filesystem::path>& worm_dir)
        : path_{path}, worm_dir_{worm_dir} {
        if (path_) {
            chain_path_ = *path_;
            chain_path_->concat(".chain");
            load_chain_state();
        }
        if (key_path && std::filesystem::exists(*key_path)) {
            std::ifstream kf{*key_path, std::ios::binary};
            std::vector<std::uint8_t> kb{(std::istreambuf_iterator<char>(kf)),
                                          std::istreambuf_iterator<char>()};
            if (kb.size() == crypto_sign_SECRETKEYBYTES) {
                std::memcpy(sk_.data(), kb.data(), kb.size());
                if (crypto_sign_ed25519_sk_to_pk(pk_.data(), sk_.data()) == 0) {
                    sign_enabled_ = true;
                }
            }
        }
        if (anchor_file) {
            std::lock_guard<std::mutex> lk{mu_};
            maybe_anchor_from_file_unlocked(anchor_file);
        }
    }

    /// @brief Append a record to the JSONL log under the running chain.
    /// @par Thread safety: Locked; safe to call concurrently.
    void log(Severity                  sev,
             const std::string&        category,
             const std::string&        subject,
             const std::string&        message) {
        std::lock_guard<std::mutex> lk{mu_};
        append_record_unlocked(sev, category, subject, message);
    }

    /// @brief Expose canonical_bytes for the free verify_chain function
    ///        so re-validation uses the same encoding as production.
    [[nodiscard]] static std::vector<std::uint8_t> canonical_bytes_public(
        const Hash32&             prev,
        std::int64_t              ts_ms,
        Severity                  sev,
        const std::string&        cat,
        const std::string&        sub,
        const std::string&        msg)
    {
        return canonical_bytes(prev, ts_ms, sev, cat, sub, msg);
    }

  private:
    void load_chain_state() {
        if (!chain_path_ || !std::filesystem::exists(*chain_path_)) {
            have_last_ = false;
            return;
        }
        std::ifstream f{*chain_path_, std::ios::binary};
        if (!f) { have_last_ = false; return; }
        f.read(reinterpret_cast<char*>(last_hash_.data()),
               static_cast<std::streamsize>(last_hash_.size()));
        have_last_ = f.gcount() == static_cast<std::streamsize>(last_hash_.size());
    }

    void save_chain_state() {
        if (!chain_path_) return;
        std::ofstream f{*chain_path_, std::ios::binary | std::ios::trunc};
        if (!f) return;
        f.write(reinterpret_cast<const char*>(last_hash_.data()),
                static_cast<std::streamsize>(last_hash_.size()));
    }

    static const char* sev_str(Severity s) noexcept {
        switch (s) {
            case Severity::INFO:     return "INFO";
            case Severity::WARN:     return "WARN";
            case Severity::ERROR:    return "ERROR";
            case Severity::SECURITY: return "SECURITY";
        }
        return "SECURITY";
    }

    /// canonical: prev || u64_le(ts_ms) || u8(sev) || 0 || cat || 0 ||
    ///            sub || 0 || msg
    static std::vector<std::uint8_t> canonical_bytes(
        const Hash32&             prev,
        std::int64_t              ts_ms,
        Severity                  sev,
        const std::string&        cat,
        const std::string&        sub,
        const std::string&        msg)
    {
        std::vector<std::uint8_t> b;
        b.insert(b.end(), prev.begin(), prev.end());
        auto put64 = [&](std::uint64_t v) {
            for (int i = 0; i < 8; ++i) {
                b.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
            }
        };
        put64(static_cast<std::uint64_t>(ts_ms));
        b.push_back(static_cast<std::uint8_t>(sev));
        b.push_back(0);
        b.insert(b.end(), cat.begin(), cat.end()); b.push_back(0);
        b.insert(b.end(), sub.begin(), sub.end()); b.push_back(0);
        b.insert(b.end(), msg.begin(), msg.end());
        return b;
    }

    static void json_escape(std::ostream& f, const std::string& s) {
        for (char c : s) {
            if (c == '"') f << '\\';
            f << c;
        }
    }

    void maybe_anchor_from_file_unlocked(
        const std::optional<std::filesystem::path>& anchor_file)
    {
        if (!anchor_file || !std::filesystem::exists(*anchor_file)) return;
        try {
            std::ifstream af{*anchor_file, std::ios::binary};
            std::vector<std::uint8_t> buf{(std::istreambuf_iterator<char>(af)),
                                            std::istreambuf_iterator<char>()};
            const std::string anchor_hex = hex_from(buf.data(), buf.size());
            append_record_unlocked(Severity::SECURITY, "ANCHOR", "TSA", anchor_hex);
        } catch (...) {
            // Anchor errors are non-fatal; the chain still starts from zero.
        }
    }

    void append_record_unlocked(Severity            sev,
                                const std::string&  category,
                                const std::string&  subject,
                                const std::string&  message)
    {
        if (!path_) return;
        std::filesystem::create_directories(path_->parent_path());
        std::ofstream f{*path_, std::ios::app};
        if (!f) return;

        const auto now = std::chrono::system_clock::now();
        const auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now.time_since_epoch()).count();

        const Hash32 prev = have_last_ ? last_hash_ : Hash32{};
        auto canon       = canonical_bytes(prev, ms, sev, category, subject, message);
        const Hash32 h   = blake2b_32(canon);

        std::array<std::uint8_t, crypto_sign_BYTES> sig{};
        bool have_sig = false;
        if (sign_enabled_) {
            unsigned long long siglen = 0;
            if (crypto_sign_detached(sig.data(), &siglen,
                                     h.data(), h.size(), sk_.data()) == 0
                && siglen == crypto_sign_BYTES) {
                have_sig = true;
            }
        }

        std::ostringstream json;
        json << "{\"ts\":" << ms
             << ",\"sev\":\""  << sev_str(sev)  << "\""
             << ",\"cat\":\""  << category      << "\""
             << ",\"sub\":\""  << subject       << "\""
             << ",\"msg\":\"";
        json_escape(json, message);
        json << "\""
             << ",\"prev\":\"" << hex_from(prev) << "\""
             << ",\"hash\":\"" << hex_from(h)    << "\"";
        if (have_sig) {
            json << ",\"sig\":\"" << hex_from(sig.data(), sig.size()) << "\""
                 << ",\"pub\":\"" << hex_from(pk_.data(),  pk_.size()) << "\"";
        }
        json << "}";
        f << json.str() << '\n';

        if (worm_dir_) {
            try {
                std::filesystem::create_directories(*worm_dir_);
                const std::string fname =
                    std::to_string(ms) + "-" + hex_from(h).substr(0, 16) + ".json";
                const auto outp = *worm_dir_ / fname;
                std::ofstream wf{outp, std::ios::binary | std::ios::trunc};
                if (wf) {
                    const auto s = json.str();
                    wf.write(s.data(), static_cast<std::streamsize>(s.size()));
                    wf.flush();
                    std::error_code ecp;
                    std::filesystem::permissions(
                        outp,
                        std::filesystem::perms::owner_write,
                        std::filesystem::perm_options::remove,
                        ecp);
                }
            } catch (...) {
                // WORM errors are non-fatal; the primary JSONL still receives the record.
            }
        }

        last_hash_  = h;
        have_last_  = true;
        save_chain_state();
    }

    std::mutex                                                       mu_;
    std::optional<std::filesystem::path>                             path_;
    std::optional<std::filesystem::path>                             chain_path_;
    std::optional<std::filesystem::path>                             worm_dir_;
    Hash32                                                           last_hash_{};
    bool                                                             have_last_      = false;
    bool                                                             sign_enabled_   = false;
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES>             sk_{};
    std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>             pk_{};
};

// -----------------------------------------------------------------------
// verify_chain — pairs with AuditLogger's emit format.
//
// Distinct from the enterprise nocturne::security::AuditLogger's
// verify_chain because the canonical-bytes encoding and JSON schema
// differ. Used by the CLI's `audit-verify` subcommand.
// -----------------------------------------------------------------------

struct VerifyChainResult {
    bool                          ok                  = false;
    std::size_t                   records_checked     = 0;
    std::optional<std::size_t>    first_failure_line;  ///< 1-based.
    std::vector<std::string>      errors;
    static constexpr std::size_t  MAX_ERRORS          = 32;
};

[[nodiscard]] inline Severity sev_from_str(const std::string& s) noexcept {
    if (s == "INFO")  return Severity::INFO;
    if (s == "WARN")  return Severity::WARN;
    if (s == "ERROR") return Severity::ERROR;
    return Severity::SECURITY;
}

[[nodiscard]] inline bool hex_decode_fixed(const std::string& hex,
                                           std::uint8_t*      out,
                                           std::size_t        out_len) noexcept
{
    if (hex.size() != out_len * 2) return false;
    const auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    for (std::size_t i = 0; i < out_len; ++i) {
        const int hi = nyb(hex[2 * i]);
        const int lo = nyb(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

/// @brief Minimal JSON field extractor tailored to the emitter above.
///
/// The emitter only escapes `"` (via json_escape), and string values
/// cannot contain newlines because records are framed line-by-line, so
/// the grammar we need to parse is narrow:
///   "<key>":"<value-with-only-\"-escaped>"   or
///   "<key>":<integer>
/// Returns false if the key isn't found or the value is malformed.
[[nodiscard]] inline bool json_extract_string(const std::string& line,
                                              const std::string& key,
                                              std::string&       out)
{
    const std::string needle = "\"" + key + "\":\"";
    const auto p = line.find(needle);
    if (p == std::string::npos) return false;
    std::size_t i = p + needle.size();
    out.clear();
    while (i < line.size()) {
        const char c = line[i];
        if (c == '\\' && i + 1 < line.size() && line[i + 1] == '"') {
            out.push_back('"');
            i += 2;
            continue;
        }
        if (c == '"') return true;
        out.push_back(c);
        ++i;
    }
    return false;
}

[[nodiscard]] inline bool json_extract_int64(const std::string& line,
                                              const std::string& key,
                                              std::int64_t&      out)
{
    const std::string needle = "\"" + key + "\":";
    const auto p = line.find(needle);
    if (p == std::string::npos) return false;
    std::size_t i = p + needle.size();
    if (i >= line.size() || line[i] == '"') return false;
    const std::size_t start = i;
    if (line[i] == '-' || line[i] == '+') ++i;
    bool any = false;
    while (i < line.size() && line[i] >= '0' && line[i] <= '9') {
        ++i;
        any = true;
    }
    if (!any) return false;
    try {
        out = std::stoll(line.substr(start, i - start));
    } catch (...) {
        return false;
    }
    return true;
}

/// @brief Walk @p log_path, reconstructing the hash chain and (when
///        present) verifying per-record Ed25519 signatures.
///
/// @param log_path           Path to the JSONL log file.
/// @param expected_signer_pk When non-nullopt, every record MUST carry
///                            a sig that verifies under this pk;
///                            unsigned records → failure.
[[nodiscard]] inline VerifyChainResult verify_chain(
    const std::filesystem::path&                                                       log_path,
    const std::optional<std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>>&         expected_signer_pk = std::nullopt)
{
    VerifyChainResult r;
    std::ifstream f{log_path};
    if (!f) {
        r.errors.push_back("cannot open " + log_path.string());
        return r;
    }

    const auto push_err = [&](std::size_t line_no, const std::string& msg) {
        if (!r.first_failure_line) r.first_failure_line = line_no;
        if (r.errors.size() < VerifyChainResult::MAX_ERRORS) {
            r.errors.push_back("line " + std::to_string(line_no) + ": " + msg);
        }
    };

    Hash32       expected_prev{};
    bool         first   = true;
    std::string  line;
    std::size_t  line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        if (line.empty()) continue;

        std::int64_t ts_ms = 0;
        std::string  sev_s, cat, sub, msg, prev_hex, hash_hex, sig_hex, pub_hex;
        if (!json_extract_int64 (line, "ts",   ts_ms))    { push_err(line_no, "missing ts");   continue; }
        if (!json_extract_string(line, "sev",  sev_s))    { push_err(line_no, "missing sev");  continue; }
        if (!json_extract_string(line, "cat",  cat))      { push_err(line_no, "missing cat");  continue; }
        if (!json_extract_string(line, "sub",  sub))      { push_err(line_no, "missing sub");  continue; }
        if (!json_extract_string(line, "msg",  msg))      { push_err(line_no, "missing msg");  continue; }
        if (!json_extract_string(line, "prev", prev_hex)) { push_err(line_no, "missing prev"); continue; }
        if (!json_extract_string(line, "hash", hash_hex)) { push_err(line_no, "missing hash"); continue; }
        (void)json_extract_string(line, "sig", sig_hex);
        (void)json_extract_string(line, "pub", pub_hex);

        Hash32 prev{}, hash{};
        if (!hex_decode_fixed(prev_hex, prev.data(), prev.size())) {
            push_err(line_no, "bad prev hex");
            continue;
        }
        if (!hex_decode_fixed(hash_hex, hash.data(), hash.size())) {
            push_err(line_no, "bad hash hex");
            continue;
        }

        if (first) {
            const Hash32 zero{};
            if (prev != zero) push_err(line_no, "first record prev != zero");
            first = false;
        } else if (prev != expected_prev) {
            push_err(line_no, "prev does not match previous record hash");
        }

        auto canon = AuditLogger::canonical_bytes_public(
            prev, ts_ms, sev_from_str(sev_s), cat, sub, msg);
        const Hash32 recomputed = blake2b_32(canon);
        if (recomputed != hash) {
            push_err(line_no, "hash mismatch (record tampered)");
        }

        if (!sig_hex.empty() && !pub_hex.empty()) {
            std::array<std::uint8_t, crypto_sign_BYTES>             sig{};
            std::array<std::uint8_t, crypto_sign_PUBLICKEYBYTES>    pk{};
            if (!hex_decode_fixed(sig_hex, sig.data(), sig.size())) {
                push_err(line_no, "bad sig hex");
            } else if (!hex_decode_fixed(pub_hex, pk.data(), pk.size())) {
                push_err(line_no, "bad pub hex");
            } else {
                if (crypto_sign_verify_detached(
                        sig.data(), hash.data(), hash.size(), pk.data()) != 0) {
                    push_err(line_no, "signature verification failed");
                }
                if (expected_signer_pk && pk != *expected_signer_pk) {
                    push_err(line_no, "signer pk does not match expected");
                }
            }
        } else if (expected_signer_pk) {
            push_err(line_no, "expected-signer set but record is unsigned");
        }

        expected_prev = hash;
        ++r.records_checked;
    }

    r.ok = r.errors.empty();
    return r;
}

// -----------------------------------------------------------------------
// Global accessors — instance lives in audit_logger.cpp.
// -----------------------------------------------------------------------

void initialize(const std::optional<std::filesystem::path>& path        = std::nullopt,
                const std::optional<std::filesystem::path>& key_path    = std::nullopt,
                const std::optional<std::filesystem::path>& anchor_file = std::nullopt,
                const std::optional<std::filesystem::path>& worm_dir    = std::nullopt);

void info    (const std::string& cat, const std::string& sub, const std::string& msg);
void warn    (const std::string& cat, const std::string& sub, const std::string& msg);
void error   (const std::string& cat, const std::string& sub, const std::string& msg);
void security(const std::string& cat, const std::string& sub, const std::string& msg);

}  // namespace audit_log
