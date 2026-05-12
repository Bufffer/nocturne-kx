/// @file rate_limiter.hpp
/// @brief In-process rate limiter used by the CLI's encrypt/decrypt
///        hot path to throttle adversarial bursts and accumulate
///        exponential-backoff penalties on persistent abuse.
///
/// **Scope.** This is the lightweight @c rate_limiting namespace that
/// the CLI consumes — distinct from any future enterprise-tier rate
/// limiter that might integrate with a distributed counter store. The
/// state lives in process memory, optionally checkpointed to a JSONL
/// file so penalty counters survive restarts.
///
/// **Thread safety.** All public entry points take an internal mutex
/// before touching shared state. Concurrent calls are safe; ordering
/// across threads is the natural last-writer-wins semantics of a
/// process-local request log.
///
/// @version 1.0.0

#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace rate_limiting {

/// @brief Tunable parameters for @ref RateLimiter.
///
/// All counters use sliding windows of the corresponding duration.
/// The `burst_limit` is checked first so a sudden spike trips the
/// penalty path even when the longer-window counts are still under
/// budget.
struct RateLimitConfig {
    std::uint32_t max_requests_per_minute   = 60;
    std::uint32_t max_requests_per_hour     = 1000;
    std::uint32_t max_requests_per_day      = 10000;
    std::uint32_t burst_limit               = 10;
    std::uint32_t burst_window_ms           = 1000;
    std::uint32_t penalty_duration_ms       = 300000;  // 5 minutes.
    bool          enable_exponential_backoff = true;
    std::uint32_t max_backoff_ms            = 60000;   // 1 minute cap.
};

/// @brief Per-identifier request log entry.
///
/// Public for serialization and inspection; treat as a record.
struct RequestEntry {
    std::chrono::steady_clock::time_point timestamp;
    std::uint32_t                         request_count       = 0;
    std::uint32_t                         penalty_count       = 0;
    std::chrono::steady_clock::time_point last_penalty;
    std::uint32_t                         current_backoff_ms  = 0;

    RequestEntry() noexcept
        : timestamp{std::chrono::steady_clock::now()},
          last_penalty{std::chrono::steady_clock::now()} {}
};

/// @brief Process-local rate limiter.
///
/// @par Thread safety: All public methods take an internal mutex.
///                     Construction is not thread-safe — establish the
///                     instance from a single thread before use.
/// @par Exception safety: Disk persistence failures are swallowed
///                        (best-effort). All other operations are
///                        nothrow under normal allocator behaviour.
class RateLimiter {
  public:
    explicit RateLimiter(
        const RateLimitConfig&                            config       = RateLimitConfig{},
        const std::optional<std::filesystem::path>&      storage_path = std::nullopt);

    /// @brief Record a request and decide whether to allow it.
    /// @return @c true if the request fits within the configured rate;
    ///         @c false when burst or window limits are tripped (and
    ///         exponential backoff starts ticking).
    [[nodiscard]] bool allow_request(const std::string& identifier);

    /// @brief Diagnostic string describing the per-identifier counters.
    [[nodiscard]] std::string get_status(const std::string& identifier);

    /// @brief Forget all state for @p identifier.
    void reset(const std::string& identifier);

    /// @brief Replace the running configuration. Existing penalties
    ///        decay under the new windows.
    void update_config(const RateLimitConfig& config);

  private:
    void          cleanup_old_entries();
    void          persist_locked();
    void          load_from_disk();
    std::uint32_t calculate_backoff(std::uint32_t penalty_count) const;

    std::unordered_map<std::string, RequestEntry> request_history_;
    std::mutex                                    mutex_;
    RateLimitConfig                               config_;
    std::optional<std::filesystem::path>          storage_path_;
    std::chrono::steady_clock::time_point         last_persist_{std::chrono::steady_clock::now()};
    std::uint32_t                                 persist_interval_ms_{60000};
};

// -----------------------------------------------------------------------
// Global limiter (process-singleton accessors).
//
// The instance lives in rate_limiter.cpp so that headers stay free of
// hidden static state. Multiple TUs including this header share the
// same global_limiter through the accessor functions below.
// -----------------------------------------------------------------------

/// @brief Lazy-initialize the process-singleton limiter. Idempotent.
void initialize(
    const RateLimitConfig&                            config       = RateLimitConfig{},
    const std::optional<std::filesystem::path>&      storage_path = std::nullopt);

/// @brief Global @ref RateLimiter::allow_request. Auto-initializes
///        with default config on first call.
[[nodiscard]] bool allow_request(const std::string& identifier);

/// @brief Global @ref RateLimiter::get_status. Returns a sentinel when
///        the global limiter has never been initialized.
[[nodiscard]] std::string get_status(const std::string& identifier);

/// @brief Global @ref RateLimiter::reset. No-op when the global
///        limiter has never been initialized.
void reset(const std::string& identifier);

}  // namespace rate_limiting
