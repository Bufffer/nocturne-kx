#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <queue>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace nocturne {
namespace transport {

using Bytes = std::vector<uint8_t>;

// Protocol versions/features
struct FeatureSet {
    uint16_t version{1};
    bool supports_ratchet{true};
    bool supports_signatures{true};
};

// Frame types
enum class FrameType : uint8_t {
    NEGOTIATE = 1,
    DATA = 2,
    ACK = 3,
    NAK = 4,
    CLOSE = 5,
};

struct FrameHeader {
    uint8_t type; // FrameType
    uint8_t flags; // reserved
    uint32_t session_id; // local session identifier
    uint64_t seq; // sequence number
};

struct NegotiatePayload {
    FeatureSet features;
};

struct AckPayload { uint64_t ack_seq; };
struct NakPayload { uint64_t nak_seq; };

struct DataPayload {
    std::vector<uint8_t> ciphertext; // already encrypted at higher layer
    std::vector<uint8_t> aad;        // optional AAD from higher layer
};

struct Frame {
    FrameHeader header{};
    std::optional<NegotiatePayload> negotiate{};
    std::optional<DataPayload> data{};
    std::optional<AckPayload> ack{};
    std::optional<NakPayload> nak{};
};

// Simple serializer (network order = LE here for consistency with rest of project)
inline void write_u32(Bytes& out, uint32_t v){ out.push_back((uint8_t)(v&0xFF)); out.push_back((uint8_t)((v>>8)&0xFF)); out.push_back((uint8_t)((v>>16)&0xFF)); out.push_back((uint8_t)((v>>24)&0xFF)); }
inline void write_u64(Bytes& out, uint64_t v){ for(int i=0;i<8;i++) out.push_back((uint8_t)((v>>(8*i))&0xFF)); }
inline uint32_t read_u32(const uint8_t* p){ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
inline uint64_t read_u64(const uint8_t* p){ uint64_t v=0; for(int i=0;i<8;i++) v |= (uint64_t)p[i] << (8*i); return v; }

inline Bytes serialize_features(const FeatureSet& f){ Bytes b; b.reserve(4); b.push_back((uint8_t)(f.version & 0xFF)); b.push_back((uint8_t)((f.version>>8)&0xFF)); b.push_back((uint8_t)f.supports_ratchet); b.push_back((uint8_t)f.supports_signatures); return b; }
inline FeatureSet parse_features(const Bytes& b){ if (b.size()!=4) throw std::runtime_error("feat size"); FeatureSet f{}; f.version = (uint16_t)(b[0] | (b[1]<<8)); f.supports_ratchet = b[2]!=0; f.supports_signatures = b[3]!=0; return f; }

inline Bytes serialize_frame(const Frame& f) {
    Bytes out; out.reserve(32);
    out.push_back(f.header.type); out.push_back(f.header.flags);
    write_u32(out, f.header.session_id); write_u64(out, f.header.seq);
    switch ((FrameType)f.header.type) {
        case FrameType::NEGOTIATE: {
            auto fb = serialize_features(f.negotiate->features);
            write_u32(out, (uint32_t)fb.size()); out.insert(out.end(), fb.begin(), fb.end());
            break;
        }
        case FrameType::DATA: {
            const auto& dp = *f.data;
            write_u32(out, (uint32_t)dp.aad.size());
            write_u32(out, (uint32_t)dp.ciphertext.size());
            out.insert(out.end(), dp.aad.begin(), dp.aad.end());
            out.insert(out.end(), dp.ciphertext.begin(), dp.ciphertext.end());
            break;
        }
        case FrameType::ACK: { write_u64(out, f.ack->ack_seq); break; }
        case FrameType::NAK: { write_u64(out, f.nak->nak_seq); break; }
        case FrameType::CLOSE: { break; }
        default: throw std::runtime_error("unknown frame type");
    }
    return out;
}

inline Frame parse_frame(const Bytes& b) {
    if (b.size() < 1+1+4+8) throw std::runtime_error("frame too short");
    Frame f{}; size_t off=0; f.header.type=b[off++]; f.header.flags=b[off++]; f.header.session_id=read_u32(&b[off]); off+=4; f.header.seq=read_u64(&b[off]); off+=8;
    auto need=[&](size_t n){ if (off+n>b.size()) throw std::runtime_error("frame truncated"); };
    switch ((FrameType)f.header.type) {
        case FrameType::NEGOTIATE: {
            need(4); uint32_t n = read_u32(&b[off]); off+=4; need(n);
            Bytes fb(b.begin()+off, b.begin()+off+n); off+=n;
            f.negotiate = NegotiatePayload{parse_features(fb)}; break;
        }
        case FrameType::DATA: {
            need(4+4); uint32_t aad_n=read_u32(&b[off]); off+=4; uint32_t ct_n=read_u32(&b[off]); off+=4; need(aad_n+ct_n);
            DataPayload dp{}; dp.aad.assign(b.begin()+off, b.begin()+off+aad_n); off+=aad_n; dp.ciphertext.assign(b.begin()+off, b.begin()+off+ct_n); off+=ct_n;
            f.data = dp; break;
        }
        case FrameType::ACK: { need(8); f.ack = AckPayload{read_u64(&b[off])}; off+=8; break; }
        case FrameType::NAK: { need(8); f.nak = NakPayload{read_u64(&b[off])}; off+=8; break; }
        case FrameType::CLOSE: { break; }
        default: throw std::runtime_error("unknown frame type");
    }
    if (off != b.size()) throw std::runtime_error("trailing bytes");
    return f;
}

// Session state and reliability
struct RetryEntry { uint64_t seq; Bytes frame; std::chrono::steady_clock::time_point last_send; uint32_t attempts{0}; };

class Session {
public:
    explicit Session(uint32_t id, FeatureSet local): id_(id), local_(local) {}

    uint32_t id() const { return id_; }
    FeatureSet negotiated() const { return negotiated_.value_or(local_); }

    // Build frames
    Frame make_negotiate() { Frame f{}; f.header={ (uint8_t)FrameType::NEGOTIATE, 0, id_, next_seq_++}; f.negotiate = NegotiatePayload{local_}; return f; }
    Frame make_data(const Bytes& aad, const Bytes& ciphertext) { Frame f{}; f.header={ (uint8_t)FrameType::DATA, 0, id_, next_seq_++}; f.data = DataPayload{ciphertext, aad}; return f; }
    Frame make_ack(uint64_t ack_seq) { Frame f{}; f.header={ (uint8_t)FrameType::ACK, 0, id_, next_seq_++}; f.ack = AckPayload{ack_seq}; return f; }
    Frame make_nak(uint64_t nak_seq) { Frame f{}; f.header={ (uint8_t)FrameType::NAK, 0, id_, next_seq_++}; f.nak = NakPayload{nak_seq}; return f; }
    Frame make_close() { Frame f{}; f.header={ (uint8_t)FrameType::CLOSE, 0, id_, next_seq_++}; return f; }

    // Process incoming frame
    std::optional<Frame> on_receive(const Frame& f) {
        // Negotiation
        if ((FrameType)f.header.type == FrameType::NEGOTIATE) {
            negotiated_ = f.negotiate->features; remote_seq_ = 0; return std::nullopt;
        }
        // Sequence checks
        if (f.header.seq <= remote_seq_) {
            // duplicate or reordering: ack last seen
            return make_ack(remote_seq_);
        }
        // Fill gaps: we can NAK the expected seq
        if (f.header.seq != remote_seq_ + 1) {
            auto nak = make_nak(remote_seq_ + 1);
            // Do not advance remote_seq_ yet
            return nak;
        }
        remote_seq_ = f.header.seq;
        // ACK data/close
        if ((FrameType)f.header.type == FrameType::DATA) {
            return make_ack(f.header.seq);
        }
        return std::nullopt;
    }

    // Reliability: track sent frames for retry
    void track_sent(const Frame& f, const Bytes& raw) {
        if ((FrameType)f.header.type == FrameType::DATA) {
            retries_.push_back(RetryEntry{f.header.seq, raw, std::chrono::steady_clock::now(), 1});
        }
    }

    // On ACK/NAK
    void handle_feedback(const Frame& f) {
        if ((FrameType)f.header.type == FrameType::ACK) {
            auto ack = f.ack->ack_seq;
            // drop all <= ack
            retries_.erase(std::remove_if(retries_.begin(), retries_.end(), [&](const RetryEntry& e){ return e.seq <= ack; }), retries_.end());
        } else if ((FrameType)f.header.type == FrameType::NAK) {
            auto want = f.nak->nak_seq;
            for (auto& e : retries_) if (e.seq == want) { e.last_send = std::chrono::steady_clock::now() - std::chrono::seconds(10); e.attempts++; }
        }
    }

    // Collect frames to retry (caller will resend)
    std::vector<Bytes> due_retries(std::chrono::milliseconds interval = std::chrono::milliseconds(500)) {
        std::vector<Bytes> out;
        auto now = std::chrono::steady_clock::now();
        for (auto& e : retries_) {
            if (now - e.last_send >= interval && e.attempts < 5) {
                e.last_send = now; out.push_back(e.frame);
            }
        }
        return out;
    }

private:
    uint32_t id_;
    FeatureSet local_{};
    std::optional<FeatureSet> negotiated_{};
    uint64_t next_seq_{1};
    uint64_t remote_seq_{0};
    std::vector<RetryEntry> retries_{};
};

// Memory transport adapter (loopback or test)
class MemoryTransport {
public:
    using SendHook = std::function<void(const Bytes&)>;

    explicit MemoryTransport(Session& sess): sess_(sess) {}

    void set_peer(MemoryTransport* peer){ peer_ = peer; }

    void set_on_data(std::function<void(const DataPayload&)> cb){ on_data_ = std::move(cb); }

    // Send a frame; internally will track for retry and deliver to peer if set
    void send(const Frame& f){
        auto raw = serialize_frame(f);
        sess_.track_sent(f, raw);
        if (peer_) peer_->receive(raw);
    }

    void receive(const Bytes& raw){
        auto f = parse_frame(raw);
        if (auto fb = sess_.on_receive(f)) {
            // feedback frame returned
            auto r = serialize_frame(*fb);
            if (peer_) peer_->receive(r);
            sess_.handle_feedback(*fb);
        }
        if ((FrameType)f.header.type == FrameType::DATA && on_data_) {
            on_data_(*f.data);
        } else if ((FrameType)f.header.type == FrameType::ACK || (FrameType)f.header.type == FrameType::NAK) {
            sess_.handle_feedback(f);
        }
    }

    // Resend due frames
    void pump_retries(){
        auto frames = sess_.due_retries();
        for (auto& raw : frames) if (peer_) peer_->receive(raw);
    }

private:
    Session& sess_;
    MemoryTransport* peer_{nullptr};
    std::function<void(const DataPayload&)> on_data_{};
};

} // namespace transport
} // namespace nocturne
