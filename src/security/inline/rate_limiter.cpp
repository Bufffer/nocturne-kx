/// @file rate_limiter.cpp
/// @brief Implementation of the in-process @ref rate_limiting subsystem
///        declared in @ref rate_limiter.hpp.
///
/// The class methods do all the bookkeeping; the global accessor
/// functions ride on top of a process-singleton instance held in this
/// TU's anonymous namespace.

#include "rate_limiter.hpp"

#include <algorithm>
#include <fstream>
#include <memory>
#include <sstream>
#include <system_error>

namespace rate_limiting {

// -----------------------------------------------------------------------
// RateLimiter — class definitions
// -----------------------------------------------------------------------

RateLimiter::RateLimiter(
    const RateLimitConfig&                            config,
    const std::optional<std::filesystem::path>&      storage_path)
    : config_{config}, storage_path_{storage_path}
{
    if (storage_path_) {
        load_from_disk();
    }
}

void RateLimiter::cleanup_old_entries() {
    const auto now     = std::chrono::steady_clock::now();
    const auto day_ago = now - std::chrono::hours{24};

    for (auto it = request_history_.begin(); it != request_history_.end();) {
        if (it->second.timestamp < day_ago) {
            it = request_history_.erase(it);
        } else {
            ++it;
        }
    }
}

void RateLimiter::persist_locked() {
    if (!storage_path_) return;
    const auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_persist_).count()
        < persist_interval_ms_) {
        return;
    }
    last_persist_ = now;
    try {
        std::filesystem::create_directories(storage_path_->parent_path());
        const std::string tmp = storage_path_->string() + ".tmp";
        std::ofstream f{tmp, std::ios::binary | std::ios::trunc};
        if (!f) return;
        for (const auto& [id, e] : request_history_) {
            const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                e.last_penalty.time_since_epoch())
                                .count();
            f << id << ',' << e.request_count << ',' << e.penalty_count << ','
              << ms << ',' << e.current_backoff_ms << '\n';
        }
        f.close();
        std::error_code ec;
        std::filesystem::rename(tmp, *storage_path_, ec);
        if (ec) {
            std::filesystem::remove(*storage_path_, ec);
            std::filesystem::rename(tmp, *storage_path_, ec);
        }
    } catch (...) {
        // Best-effort persistence; failures must not break in-memory
        // accounting. A future revision could surface this through the
        // audit log.
    }
}

void RateLimiter::load_from_disk() {
    if (!storage_path_ || !std::filesystem::exists(*storage_path_)) return;
    try {
        std::ifstream f{*storage_path_};
        if (!f) return;
        request_history_.clear();
        std::string line;
        while (std::getline(f, line)) {
            std::istringstream iss{line};
            std::string id;
            std::getline(iss, id, ',');
            std::string s_req, s_pen, s_last, s_back;
            std::getline(iss, s_req,  ',');
            std::getline(iss, s_pen,  ',');
            std::getline(iss, s_last, ',');
            std::getline(iss, s_back, ',');

            RequestEntry e;
            e.request_count = s_req.empty()  ? 0 : static_cast<std::uint32_t>(std::stoul(s_req));
            e.penalty_count = s_pen.empty()  ? 0 : static_cast<std::uint32_t>(std::stoul(s_pen));
            const long long last_ms =
                s_last.empty() ? 0 : std::stoll(s_last);
            e.last_penalty = std::chrono::steady_clock::time_point{std::chrono::milliseconds{last_ms}};
            e.current_backoff_ms =
                s_back.empty() ? 0 : static_cast<std::uint32_t>(std::stoul(s_back));
            request_history_[id] = e;
        }
    } catch (...) {
        // Corrupt or partially-written file: discard and start fresh.
    }
}

std::uint32_t RateLimiter::calculate_backoff(std::uint32_t penalty_count) const {
    if (!config_.enable_exponential_backoff || penalty_count == 0) {
        return 0;
    }
    constexpr std::uint32_t base_delay = 1000;  // 1 s base.
    const std::uint32_t backoff = base_delay
        * (1u << std::min<std::uint32_t>(penalty_count, 10));
    return std::min(backoff, config_.max_backoff_ms);
}

bool RateLimiter::allow_request(const std::string& identifier) {
    std::lock_guard<std::mutex> lock{mutex_};

    const auto now = std::chrono::steady_clock::now();

    // Opportunistic cleanup MUST run before we bind a reference into the
    // map. cleanup_old_entries() can erase this identifier's row when it is
    // older than the 24h window; binding `entry` first and cleaning up
    // afterwards left a dangling reference (use-after-free) on the
    // accounting writes below.
    if (auto existing = request_history_.find(identifier);
        existing != request_history_.end() &&
        now - existing->second.timestamp > std::chrono::hours{1}) {
        cleanup_old_entries();
    }

    auto& entry = request_history_[identifier];

    if (entry.penalty_count > 0) {
        const auto time_since_penalty = now - entry.last_penalty;
        const auto penalty_duration   = std::chrono::milliseconds{config_.penalty_duration_ms};
        if (time_since_penalty < penalty_duration) {
            const auto backoff_duration = std::chrono::milliseconds{entry.current_backoff_ms};
            if (time_since_penalty < backoff_duration) {
                return false;
            }
        } else {
            entry.penalty_count      = 0;
            entry.current_backoff_ms = 0;
        }
    }

    entry.request_count++;
    entry.timestamp = now;

    if (entry.request_count > config_.burst_limit) {
        entry.penalty_count++;
        entry.last_penalty       = now;
        entry.current_backoff_ms = calculate_backoff(entry.penalty_count);
        return false;
    }

    const auto minute_ago = now - std::chrono::minutes{1};
    const auto hour_ago   = now - std::chrono::hours{1};
    const auto day_ago    = now - std::chrono::hours{24};

    const std::uint32_t requests_last_minute = entry.timestamp > minute_ago ? entry.request_count : 0;
    const std::uint32_t requests_last_hour   = entry.timestamp > hour_ago   ? entry.request_count : 0;
    const std::uint32_t requests_last_day    = entry.timestamp > day_ago    ? entry.request_count : 0;

    if (requests_last_minute > config_.max_requests_per_minute ||
        requests_last_hour   > config_.max_requests_per_hour   ||
        requests_last_day    > config_.max_requests_per_day) {
        entry.penalty_count++;
        entry.last_penalty       = now;
        entry.current_backoff_ms = calculate_backoff(entry.penalty_count);
        return false;
    }

    persist_locked();
    return true;
}

std::string RateLimiter::get_status(const std::string& identifier) {
    std::lock_guard<std::mutex> lock{mutex_};
    auto it = request_history_.find(identifier);
    if (it == request_history_.end()) {
        return "No requests recorded";
    }
    const auto& entry = it->second;
    std::ostringstream oss;
    oss << "Requests: " << entry.request_count
        << ", Penalties: " << entry.penalty_count
        << ", Backoff: " << entry.current_backoff_ms << "ms";
    return oss.str();
}

void RateLimiter::reset(const std::string& identifier) {
    std::lock_guard<std::mutex> lock{mutex_};
    request_history_.erase(identifier);
}

void RateLimiter::update_config(const RateLimitConfig& config) {
    std::lock_guard<std::mutex> lock{mutex_};
    config_ = config;
}

// -----------------------------------------------------------------------
// Global accessor functions
// -----------------------------------------------------------------------

namespace {
// Lives in this TU only; multiple consumers see the same instance via
// the accessor functions below.
std::unique_ptr<RateLimiter> g_limiter;
}  // namespace

void initialize(
    const RateLimitConfig&                            config,
    const std::optional<std::filesystem::path>&      storage_path)
{
    if (!g_limiter) {
        g_limiter = std::make_unique<RateLimiter>(config, storage_path);
    }
}

bool allow_request(const std::string& identifier) {
    if (!g_limiter) {
        initialize();
    }
    return g_limiter->allow_request(identifier);
}

std::string get_status(const std::string& identifier) {
    if (!g_limiter) {
        return "Rate limiter not initialized";
    }
    return g_limiter->get_status(identifier);
}

void reset(const std::string& identifier) {
    if (g_limiter) {
        g_limiter->reset(identifier);
    }
}

}  // namespace rate_limiting
