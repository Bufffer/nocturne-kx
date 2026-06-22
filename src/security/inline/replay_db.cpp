/// @file replay_db.cpp
/// @brief Implementations for the @ref replay_db.hpp encrypted counter
///        store.

#include "replay_db.hpp"

#include "../../core/file_io.hpp"
#include "../../core/side_channel.hpp"
#include "../../protocol/packet.hpp"  // write_u64_le / write_u32_le / read_u64_le / read_u32_le

#include <cstring>
#include <stdexcept>
#include <system_error>

namespace nocturne {

ReplayDB::ReplayDB(std::filesystem::path                       p,
                   const std::optional<std::filesystem::path>& keyfile,
                   const std::optional<std::filesystem::path>& tpm_counter_path)
    : path_{std::move(p)}, tpm_counter_path_{tpm_counter_path}
{
    try {
        std::filesystem::create_directories(path_.parent_path());
    } catch (...) {
        // Directory creation is best-effort; the subsequent persist will
        // surface a real I/O failure with a useful message.
    }

    if (keyfile && std::filesystem::exists(*keyfile)) {
        const auto k = read_all(*keyfile);
        if (k.size() == mac_key_.size()) {
            std::memcpy(mac_key_.data(), k.data(), mac_key_.size());
        } else {
            throw std::runtime_error{"mac key size mismatch"};
        }
    } else {
        // Transient key; NOT SECURE for production — every run yields a
        // fresh key, so the on-disk DB cannot be validated across
        // restarts. Use a real keyfile in deployment.
        crypto_generichash_keygen(mac_key_.data());
    }

    // Derive metadata-encryption key from MAC key.
    static constexpr char kEncInfo[] = "replaydb-enc";
    if (crypto_generichash(enc_key_.data(), enc_key_.size(),
                           mac_key_.data(), mac_key_.size(),
                           reinterpret_cast<const std::uint8_t*>(kEncInfo),
                           sizeof(kEncInfo) - 1) != 0) {
        throw std::runtime_error{"enc key derivation failed"};
    }

    load();
}

ReplayDB::~ReplayDB() {
    side_channel::secure_zero_memory(mac_key_.data(), mac_key_.size());
    side_channel::secure_zero_memory(enc_key_.data(), enc_key_.size());
}

void ReplayDB::load() {
    std::lock_guard<std::mutex> lk{mu_};
    m_.clear();
    if (!std::filesystem::exists(path_)) return;

    const auto raw = read_all(path_);
    if (raw.size() < 16) throw std::runtime_error{"db too small or corrupted"};
    const std::uint8_t* p = raw.data();
    const std::uint64_t file_version = read_u64_le(p);
    p += 8;
    const bool is_encrypted = (file_version & (1ULL << 63)) != 0;

    if (tpm_counter_path_ && std::filesystem::exists(*tpm_counter_path_)) {
        const auto cbuf = read_all(*tpm_counter_path_);
        if (cbuf.size() >= 8) {
            const std::uint64_t tpm_v  = read_u64_le(cbuf.data());
            const std::uint64_t fv_plain = file_version & ~(1ULL << 63);
            if (fv_plain < tpm_v) {
                audit_log::security("ReplayDB", "rollback",
                                    "External monotonic counter indicates rollback");
                throw std::runtime_error{"replaydb rollback detected by external counter"};
            }
        }
    }

    std::string json_s;
    if (!is_encrypted) {
        // Legacy: [8B version][4B json_len][json][mac]
        const std::uint32_t json_len = read_u32_le(p);
        p += 4;
        if (raw.size() < 8 + 4 + json_len + crypto_generichash_BYTES) {
            throw std::runtime_error{"db truncated"};
        }
        const std::uint8_t* json_ptr = p;
        p += json_len;
        const std::uint8_t* mac_ptr = p;

        std::array<std::uint8_t, crypto_generichash_BYTES> mac{};
        if (crypto_generichash(mac.data(), mac.size(),
                               raw.data(), 8 + 4 + json_len,
                               mac_key_.data(), mac_key_.size()) != 0) {
            throw std::runtime_error{"mac calc failed"};
        }
        if (!side_channel::constant_time_compare(mac.data(), mac_ptr, mac.size())) {
            side_channel::random_delay();
            throw std::runtime_error{"replaydb MAC mismatch"};
        }
        json_s.assign(reinterpret_cast<const char*>(json_ptr), json_len);
    } else {
        // Encrypted: [8B version (MSB=1)][24B nonce][4B ct_len][ct]
        std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> npub{};
        if (raw.size() < 8 + npub.size() + 4) throw std::runtime_error{"db truncated"};
        std::memcpy(npub.data(), p, npub.size());
        p += npub.size();
        const std::uint32_t ct_len = read_u32_le(p);
        p += 4;
        if (raw.size() < 8 + npub.size() + 4 + ct_len) {
            throw std::runtime_error{"db truncated"};
        }
        const std::uint8_t* ct_ptr     = p;
        const std::uint64_t ver_plain  = file_version & ~(1ULL << 63);

        std::vector<std::uint8_t> pt(ct_len - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long        pt_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                pt.data(), &pt_len, nullptr,
                ct_ptr, ct_len,
                reinterpret_cast<const unsigned char*>(&ver_plain), sizeof(ver_plain),
                npub.data(), enc_key_.data()) != 0) {
            throw std::runtime_error{"db decrypt failed"};
        }
        pt.resize(static_cast<std::size_t>(pt_len));
        json_s.assign(reinterpret_cast<const char*>(pt.data()), pt.size());
    }

    std::istringstream iss{json_s};
    std::string        line;
    while (std::getline(iss, line)) {
        // Composite keys may contain ':' (rx=tx:hex&snd=-&sid=-), so
        // split on the LAST colon — the counter is always trailing.
        const auto pos = line.rfind(':');
        if (pos == std::string::npos) continue;
        const std::string k       = line.substr(0, pos);
        const std::string val_str = line.substr(pos + 1);
        if (val_str.empty()) continue;
        try {
            const std::uint64_t v = std::stoull(val_str);
            m_[k] = v;
        } catch (const std::exception&) {
            // Skip malformed entries silently — operator should run
            // audit-verify if they want to know about it.
        }
    }
    version_ = file_version;
}

void ReplayDB::persist_unlocked() {
    std::ostringstream oss;
    for (const auto& [k, v] : m_) oss << k << ':' << v << '\n';
    const std::string js = oss.str();

    std::array<std::uint8_t, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> npub{};
    randombytes_buf(npub.data(), npub.size());

    std::vector<std::uint8_t> ct(js.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long         ct_len = 0;
    const std::uint64_t        v      = ++version_;
    const std::uint64_t        v_enc  = v | (1ULL << 63);
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct.data(), &ct_len,
            reinterpret_cast<const unsigned char*>(js.data()), js.size(),
            reinterpret_cast<const unsigned char*>(&v), sizeof(v),
            nullptr,
            npub.data(), enc_key_.data()) != 0) {
        throw std::runtime_error{"db encrypt failed"};
    }
    ct.resize(static_cast<std::size_t>(ct_len));

    Bytes buf;
    buf.reserve(8 + npub.size() + 4 + ct.size());
    write_u64_le(buf, v_enc);
    buf.insert(buf.end(), npub.begin(), npub.end());
    write_u32_le(buf, static_cast<std::uint32_t>(ct.size()));
    buf.insert(buf.end(), ct.begin(), ct.end());

    const std::string tmp = db_temp_path(path_);
    {
        std::ofstream f{tmp, std::ios::binary | std::ios::trunc};
        if (!f) throw std::runtime_error{"open tmp db failed"};
        f.write(reinterpret_cast<const char*>(buf.data()),
                static_cast<std::streamsize>(buf.size()));
        f.flush();
        if (!f) throw std::runtime_error{"write tmp db failed"};
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path_, ec);
    if (ec) {
        std::filesystem::remove(path_, ec);
        std::filesystem::rename(tmp, path_, ec);
        if (ec) throw std::runtime_error{"atomic rename failed: " + ec.message()};
    }

    if (tpm_counter_path_) {
        try {
            const std::string ctmp = tpm_counter_path_->string() + ".tmp";
            Bytes              cbuf;
            cbuf.reserve(8);
            write_u64_le(cbuf, v);
            {
                std::ofstream f{ctmp, std::ios::binary | std::ios::trunc};
                if (f) {
                    f.write(reinterpret_cast<const char*>(cbuf.data()),
                            static_cast<std::streamsize>(cbuf.size()));
                    f.flush();
                }
            }
            std::error_code ec2;
            std::filesystem::rename(ctmp, *tpm_counter_path_, ec2);
            if (ec2) {
                std::filesystem::remove(*tpm_counter_path_, ec2);
                std::filesystem::rename(ctmp, *tpm_counter_path_, ec2);
            }
        } catch (...) {
            audit_log::warn("ReplayDB", "counter",
                            "Failed to update external monotonic counter");
        }
    }
}

void ReplayDB::persist() {
    std::lock_guard<std::mutex> lk{mu_};
    persist_unlocked();
}

std::uint64_t ReplayDB::get(const std::string& hexpk) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto composite = make_scope_key(hexpk, std::nullopt, std::nullopt);
    const auto it        = m_.find(composite);
    return it == m_.end() ? 0 : it->second;
}

void ReplayDB::set(const std::string& hexpk, std::uint64_t v) {
    std::lock_guard<std::mutex> lk{mu_};
    const auto composite = make_scope_key(hexpk, std::nullopt, std::nullopt);
    m_[composite] = v;
    persist_unlocked();
}

std::uint64_t ReplayDB::get_scoped(const std::string&                rx_hex,
                                    const std::optional<std::string>& sender_pk_hex,
                                    const std::optional<std::string>& session_id)
{
    std::lock_guard<std::mutex> lk{mu_};
    const auto key = make_scope_key(rx_hex, sender_pk_hex, session_id);
    const auto it  = m_.find(key);
    return it == m_.end() ? 0 : it->second;
}

void ReplayDB::set_scoped(const std::string&                rx_hex,
                          const std::optional<std::string>& sender_pk_hex,
                          const std::optional<std::string>& session_id,
                          std::uint64_t                      v)
{
    std::lock_guard<std::mutex> lk{mu_};
    const auto key = make_scope_key(rx_hex, sender_pk_hex, session_id);
    m_[key] = v;
    persist_unlocked();
}

}  // namespace nocturne
