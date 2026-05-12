/// @file audit_logger.cpp
/// @brief Global process-singleton storage for the in-process audit
///        logger declared in @ref audit_logger.hpp.
///
/// The AuditLogger class itself is fully inline in the header (it's
/// self-contained and used in a single TU per build target). Only the
/// one piece of global mutable state — the singleton pointer — and the
/// thin free-function accessors live in this TU.

#include "audit_logger.hpp"

#include <memory>

namespace audit_log {

namespace {
std::unique_ptr<AuditLogger> g_logger;
}  // namespace

void initialize(const std::optional<std::filesystem::path>& path,
                const std::optional<std::filesystem::path>& key_path,
                const std::optional<std::filesystem::path>& anchor_file,
                const std::optional<std::filesystem::path>& worm_dir)
{
    if (!g_logger) {
        g_logger = std::make_unique<AuditLogger>(path, key_path, anchor_file, worm_dir);
    }
}

void info(const std::string& cat, const std::string& sub, const std::string& msg) {
    if (!g_logger) return;
    g_logger->log(Severity::INFO, cat, sub, msg);
}

void warn(const std::string& cat, const std::string& sub, const std::string& msg) {
    if (!g_logger) return;
    g_logger->log(Severity::WARN, cat, sub, msg);
}

void error(const std::string& cat, const std::string& sub, const std::string& msg) {
    if (!g_logger) return;
    g_logger->log(Severity::ERROR, cat, sub, msg);
}

void security(const std::string& cat, const std::string& sub, const std::string& msg) {
    if (!g_logger) return;
    g_logger->log(Severity::SECURITY, cat, sub, msg);
}

}  // namespace audit_log
