#ifndef NOCTURNE_SECURITY_SIEM_CONNECTOR_HPP
#define NOCTURNE_SECURITY_SIEM_CONNECTOR_HPP

#include "audit_logger.hpp"
#include <sstream>
#include <iomanip>
#include <ctime>

namespace nocturne {
namespace security {

/**
 * @brief Syslog Facility (RFC 5424)
 */
enum class SyslogFacility {
    KERN = 0,       ///< Kernel messages
    USER = 1,       ///< User-level messages
    MAIL = 2,       ///< Mail system
    DAEMON = 3,     ///< System daemons
    AUTH = 4,       ///< Security/authorization
    SYSLOG = 5,     ///< Internal syslog
    LPR = 6,        ///< Line printer
    NEWS = 7,       ///< Network news
    UUCP = 8,       ///< UUCP subsystem
    CRON = 9,       ///< Cron daemon
    AUTHPRIV = 10,  ///< Security/authorization (private)
    FTP = 11,       ///< FTP daemon
    LOCAL0 = 16,    ///< Local use 0
    LOCAL1 = 17,    ///< Local use 1
    LOCAL2 = 18,    ///< Local use 2
    LOCAL3 = 19,    ///< Local use 3
    LOCAL4 = 20,    ///< Local use 4
    LOCAL5 = 21,    ///< Local use 5
    LOCAL6 = 22,    ///< Local use 6
    LOCAL7 = 23     ///< Local use 7
};

/**
 * @brief SIEM Connector for various SIEM platforms
 */
class SIEMConnector {
private:
    SIEMConfig config_;

    /**
     * @brief Map audit severity to syslog priority
     */
    int audit_to_syslog_priority(AuditSeverity sev) const {
        switch (sev) {
            case AuditSeverity::EMERGENCY: return 0;
            case AuditSeverity::ALERT: return 1;
            case AuditSeverity::CRITICAL: return 2;
            case AuditSeverity::ERROR: return 3;
            case AuditSeverity::WARNING: return 4;
            case AuditSeverity::NOTICE: return 5;
            case AuditSeverity::INFO: return 6;
            case AuditSeverity::DEBUG: return 7;
            case AuditSeverity::SECURITY: return 1; // Map to ALERT
            default: return 6;
        }
    }

    /**
     * @brief Get syslog facility code
     */
    int get_facility_code() const {
        // Default to LOCAL0 (security applications)
        return static_cast<int>(SyslogFacility::LOCAL0);
    }

    /**
     * @brief Format record as RFC 5424 syslog message
     */
    std::string to_syslog_rfc5424(const AuditRecord& record) const {
        std::ostringstream msg;

        // Priority = (Facility * 8) + Severity
        int facility = get_facility_code();
        int priority_value = audit_to_syslog_priority(record.severity);
        int pri = (facility * 8) + priority_value;

        msg << "<" << pri << ">1 "; // Priority + Version

        // Timestamp (ISO 8601)
        auto time_t = std::chrono::system_clock::to_time_t(record.timestamp);
        std::tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &time_t);
#else
        gmtime_r(&time_t, &tm_buf);
#endif
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            record.timestamp.time_since_epoch()).count() % 1000;

        msg << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
        msg << "." << std::setfill('0') << std::setw(3) << ms << "Z ";

        // Hostname (use "nocturne-kx" as default)
        msg << config_.application_name << " ";

        // App name
        msg << config_.application_name << " ";

        // Process ID (use sequence number)
        msg << record.sequence_number << " ";

        // Message ID
        msg << record.category << ":" << record.action << " ";

        // Structured data
        msg << "[nocturne@0";
        msg << " cat=\"" << syslog_escape(record.category) << "\"";
        msg << " act=\"" << syslog_escape(record.action) << "\"";
        msg << " sub=\"" << syslog_escape(record.subject) << "\"";
        msg << " obj=\"" << syslog_escape(record.object) << "\"";
        msg << " res=\"" << syslog_escape(record.result) << "\"";
        msg << " seq=\"" << record.sequence_number << "\"";

        if (record.error_code) {
            msg << " err=\"" << syslog_escape(*record.error_code) << "\"";
        }
        if (record.source_ip) {
            msg << " src=\"" << syslog_escape(*record.source_ip) << "\"";
        }

        msg << "] ";

        // Message
        msg << syslog_escape(record.message);

        return msg.str();
    }

    /**
     * @brief Format record as CEF (Common Event Format)
     * Used by ArcSight, Splunk, QRadar
     */
    std::string to_cef(const AuditRecord& record) const {
        std::ostringstream msg;

        // CEF Header: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        msg << "CEF:0|";
        msg << "Anthropic|";                          // Vendor
        msg << "Nocturne-KX|";                        // Product
        msg << "3.0.0|";                              // Version
        msg << record.category << ":" << record.action << "|"; // Signature ID
        msg << record.category << " " << record.action << "|"; // Name

        // CEF Severity (0-10 scale)
        int cef_severity = std::min(10, static_cast<int>(record.severity));
        msg << cef_severity << "|";

        // Extensions (key=value pairs)
        std::vector<std::string> extensions;

        extensions.push_back("act=" + cef_escape(record.action));
        extensions.push_back("cat=" + cef_escape(record.category));
        extensions.push_back("suser=" + cef_escape(record.subject));
        extensions.push_back("duser=" + cef_escape(record.object));
        extensions.push_back("outcome=" + cef_escape(record.result));
        extensions.push_back("msg=" + cef_escape(record.message));

        if (record.error_code) {
            extensions.push_back("reason=" + cef_escape(*record.error_code));
        }
        if (record.source_ip) {
            extensions.push_back("src=" + cef_escape(*record.source_ip));
        }
        if (record.duration_microseconds) {
            extensions.push_back("rt=" + std::to_string(*record.duration_microseconds));
        }
        if (record.bytes_processed) {
            extensions.push_back("in=" + std::to_string(*record.bytes_processed));
        }

        // Custom extensions
        extensions.push_back("cs1Label=SequenceNumber");
        extensions.push_back("cs1=" + std::to_string(record.sequence_number));

        extensions.push_back("cs2Label=Hash");
        extensions.push_back("cs2=" + hex_encode(record.current_hash.data(), 32));

        // Join extensions
        bool first = true;
        for (const auto& ext : extensions) {
            if (!first) msg << " ";
            msg << ext;
            first = false;
        }

        return msg.str();
    }

    /**
     * @brief Format record as LEEF (Log Event Extended Format)
     * Used by IBM QRadar
     */
    std::string to_leef(const AuditRecord& record) const {
        std::ostringstream msg;

        // LEEF Header: LEEF:Version|Vendor|Product|Version|EventID|
        msg << "LEEF:2.0|";
        msg << "Anthropic|";
        msg << "Nocturne-KX|";
        msg << "3.0.0|";
        msg << record.category << ":" << record.action << "|";

        // Attributes (tab-separated key=value pairs)
        std::vector<std::string> attrs;

        attrs.push_back("devTime=" + format_leef_time(record.timestamp));
        attrs.push_back("cat=" + leef_escape(record.category));
        attrs.push_back("action=" + leef_escape(record.action));
        attrs.push_back("usrName=" + leef_escape(record.subject));
        attrs.push_back("resource=" + leef_escape(record.object));
        attrs.push_back("result=" + leef_escape(record.result));
        attrs.push_back("msg=" + leef_escape(record.message));
        attrs.push_back("sev=" + std::to_string(static_cast<int>(record.severity)));
        attrs.push_back("seq=" + std::to_string(record.sequence_number));

        if (record.error_code) {
            attrs.push_back("reason=" + leef_escape(*record.error_code));
        }
        if (record.source_ip) {
            attrs.push_back("srcIP=" + leef_escape(*record.source_ip));
        }

        // Join with tabs
        for (size_t i = 0; i < attrs.size(); ++i) {
            if (i > 0) msg << "\t";
            msg << attrs[i];
        }

        return msg.str();
    }

    /**
     * @brief Format record for Splunk HEC (HTTP Event Collector)
     */
    std::string to_splunk_hec(const AuditRecord& record) const {
        std::ostringstream json;

        json << "{";
        json << "\"time\":" << std::chrono::duration_cast<std::chrono::seconds>(
            record.timestamp.time_since_epoch()).count() << ",";
        json << "\"host\":\"" << config_.application_name << "\",";
        json << "\"source\":\"nocturne-kx\",";
        json << "\"sourcetype\":\"nocturne:audit\",";
        json << "\"event\":{";
        json << "\"seq\":" << record.sequence_number << ",";
        json << "\"severity\":\"" << severity_to_string(record.severity) << "\",";
        json << "\"category\":\"" << json_escape(record.category) << "\",";
        json << "\"action\":\"" << json_escape(record.action) << "\",";
        json << "\"subject\":\"" << json_escape(record.subject) << "\",";
        json << "\"object\":\"" << json_escape(record.object) << "\",";
        json << "\"result\":\"" << json_escape(record.result) << "\",";
        json << "\"message\":\"" << json_escape(record.message) << "\"";

        if (record.error_code) {
            json << ",\"error_code\":\"" << json_escape(*record.error_code) << "\"";
        }
        if (record.source_ip) {
            json << ",\"source_ip\":\"" << json_escape(*record.source_ip) << "\"";
        }

        json << "}";
        json << "}";

        return json.str();
    }

    /**
     * @brief Escape string for syslog
     */
    std::string syslog_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            if (c == '"' || c == '\\' || c == ']') {
                escaped << '\\';
            }
            escaped << c;
        }
        return escaped.str();
    }

    /**
     * @brief Escape string for CEF
     */
    std::string cef_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            if (c == '\\' || c == '=' || c == '\n' || c == '\r') {
                escaped << '\\';
            }
            escaped << c;
        }
        return escaped.str();
    }

    /**
     * @brief Escape string for LEEF
     */
    std::string leef_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            if (c == '\\' || c == '\t' || c == '\n' || c == '\r') {
                escaped << '\\';
            }
            escaped << c;
        }
        return escaped.str();
    }

    /**
     * @brief JSON escape
     */
    std::string json_escape(const std::string& s) const {
        std::ostringstream escaped;
        for (char c : s) {
            switch (c) {
                case '"': escaped << "\\\""; break;
                case '\\': escaped << "\\\\"; break;
                case '\b': escaped << "\\b"; break;
                case '\f': escaped << "\\f"; break;
                case '\n': escaped << "\\n"; break;
                case '\r': escaped << "\\r"; break;
                case '\t': escaped << "\\t"; break;
                default: escaped << c;
            }
        }
        return escaped.str();
    }

    /**
     * @brief Hex encode
     */
    std::string hex_encode(const uint8_t* data, size_t len) const {
        static const char* hex_chars = "0123456789abcdef";
        std::string hex;
        hex.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            hex.push_back(hex_chars[(data[i] >> 4) & 0x0F]);
            hex.push_back(hex_chars[data[i] & 0x0F]);
        }
        return hex;
    }

    /**
     * @brief Format timestamp for LEEF
     */
    std::string format_leef_time(std::chrono::system_clock::time_point tp) const {
        auto time_t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm_buf;
#ifdef _WIN32
        gmtime_s(&tm_buf, &time_t);
#else
        gmtime_r(&time_t, &tm_buf);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    /**
     * @brief Severity to string
     */
    const char* severity_to_string(AuditSeverity sev) const {
        switch (sev) {
            case AuditSeverity::DEBUG: return "DEBUG";
            case AuditSeverity::INFO: return "INFO";
            case AuditSeverity::NOTICE: return "NOTICE";
            case AuditSeverity::WARNING: return "WARNING";
            case AuditSeverity::ERROR: return "ERROR";
            case AuditSeverity::CRITICAL: return "CRITICAL";
            case AuditSeverity::ALERT: return "ALERT";
            case AuditSeverity::EMERGENCY: return "EMERGENCY";
            case AuditSeverity::SECURITY: return "SECURITY";
            default: return "UNKNOWN";
        }
    }

public:
    explicit SIEMConnector(const SIEMConfig& config) : config_(config) {}

    /**
     * @brief Send record to SIEM
     * @note This is a synchronous call. In production, use async queue.
     */
    void send(const AuditRecord& record) {
        std::string formatted;

        switch (config_.type) {
            case SIEMType::SYSLOG_UDP:
            case SIEMType::SYSLOG_TCP:
            case SIEMType::SYSLOG_TLS:
                formatted = to_syslog_rfc5424(record);
                break;

            case SIEMType::CEF:
                formatted = to_cef(record);
                break;

            case SIEMType::LEEF:
                formatted = to_leef(record);
                break;

            case SIEMType::SPLUNK_HEC:
                formatted = to_splunk_hec(record);
                break;

            default:
                return; // No SIEM configured
        }

        // TODO: Actual network send
        // For UDP syslog: sendto()
        // For TCP/TLS syslog: SSL_write()
        // For HTTP (Splunk HEC): libcurl POST request
        // For Kafka: kafka producer

        // Placeholder: print to stderr for now
        // std::cerr << "[SIEM] " << formatted << std::endl;

        (void)formatted; // Suppress unused warning
    }

    /**
     * @brief Format record for specific SIEM type
     */
    std::string format(const AuditRecord& record, SIEMType type) const {
        switch (type) {
            case SIEMType::SYSLOG_UDP:
            case SIEMType::SYSLOG_TCP:
            case SIEMType::SYSLOG_TLS:
                return to_syslog_rfc5424(record);

            case SIEMType::CEF:
                return to_cef(record);

            case SIEMType::LEEF:
                return to_leef(record);

            case SIEMType::SPLUNK_HEC:
                return to_splunk_hec(record);

            default:
                return "";
        }
    }
};

} // namespace security
} // namespace nocturne

#endif // NOCTURNE_SECURITY_SIEM_CONNECTOR_HPP
