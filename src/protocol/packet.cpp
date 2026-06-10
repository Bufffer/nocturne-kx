/// @file packet.cpp
/// @brief serialize() / deserialize() implementations matching the wire
///        layout documented in @ref packet.hpp.
///
/// The deserializer is the project's trust boundary for adversarial
/// bytes. Every bounds check, size cap, and integer-overflow guard
/// lives here — each reject is a typed `Result` error, never an
/// exception. Adding a field to the wire format means editing both
/// halves of this file plus the @c Packet struct in the header — keep
/// them in lockstep.

#include "packet.hpp"

#include <cstdint>
#include <cstring>

namespace nocturne {

namespace {

// Defensive size caps used during parse. The header's MAX_PQC_*_SIZE
// constants are the public knobs; these mirror the existing AAD /
// ciphertext caps that lived in nocturne-kx.cpp's local constants.
inline constexpr std::size_t MAX_PACKET_SIZE     = 1 * 1024 * 1024;  // 1 MiB
inline constexpr std::size_t MAX_AAD_SIZE        = 64 * 1024;        // 64 KiB
inline constexpr std::size_t MAX_CIPHERTEXT_SIZE = 1 * 1024 * 1024;  // 1 MiB

}  // namespace

[[nodiscard]] Result<Bytes> serialize(const Packet& p) {
    const Flag flags = flag_from_byte(p.flags);

    if (has_any(flags, Flag::HasRatchet) && !p.ratchet_pk) {
        return err(ErrorCode::PacketFlagInconsistent,
                   "ratchet flag set but pk missing");
    }
    if (has_any(flags, Flag::HasPqcKem)) {
        if (p.pqc_kem_ct.empty()) {
            return err(ErrorCode::PacketFlagInconsistent,
                       "pqc-kem flag set but ct missing");
        }
        if (p.pqc_kem_ct.size() > MAX_PQC_KEM_CT_SIZE) {
            return err(ErrorCode::PacketFieldOversized, "pqc kem ct too large");
        }
    }
    if (has_any(flags, Flag::HasPqcSig)) {
        if (p.pqc_sig.empty()) {
            return err(ErrorCode::PacketFlagInconsistent,
                       "pqc-sig flag set but bytes missing");
        }
        if (p.pqc_sig.size() > MAX_PQC_SIG_SIZE) {
            return err(ErrorCode::PacketFieldOversized, "pqc sig too large");
        }
    }
    if (has_any(flags, Flag::HasSig) && !p.signature) {
        return err(ErrorCode::PacketFlagInconsistent,
                   "flag set but signature missing");
    }

    Bytes out;
    out.reserve(
        1 + 1 + 4
        + p.eph_pk.size()
        + p.nonce.size()
        + 8
        + (p.ratchet_pk ? crypto_kx_PUBLICKEYBYTES : 0)
        + (has_any(flags, Flag::HasPqcKem) ? (1 + 4 + p.pqc_kem_ct.size()) : 0)
        + 4 + 4
        + p.aad.size()
        + p.ciphertext.size()
        + (has_any(flags, Flag::HasPqcSig) ? (1 + 4 + p.pqc_sig.size()) : 0)
        + (p.signature ? crypto_sign_BYTES : 0));

    out.push_back(p.version);
    out.push_back(p.flags);
    write_u32_le(out, p.rotation_id);
    out.insert(out.end(), p.eph_pk.begin(), p.eph_pk.end());
    out.insert(out.end(), p.nonce.begin(), p.nonce.end());
    write_u64_le(out, p.counter);

    if (has_any(flags, Flag::HasRatchet)) {
        out.insert(out.end(), p.ratchet_pk->begin(), p.ratchet_pk->end());
    }

    if (has_any(flags, Flag::HasPqcKem)) {
        out.push_back(p.pqc_kem_type);
        write_u32_le(out, static_cast<std::uint32_t>(p.pqc_kem_ct.size()));
        out.insert(out.end(), p.pqc_kem_ct.begin(), p.pqc_kem_ct.end());
    }

    write_u32_le(out, static_cast<std::uint32_t>(p.aad.size()));
    write_u32_le(out, static_cast<std::uint32_t>(p.ciphertext.size()));
    if (!p.aad.empty()) {
        out.insert(out.end(), p.aad.begin(), p.aad.end());
    }
    if (!p.ciphertext.empty()) {
        out.insert(out.end(), p.ciphertext.begin(), p.ciphertext.end());
    }

    // PQC signature block before the classical signature: when both
    // flags are set (currently not exercised but reserved), stripping
    // the classical sig for canonical re-serialization still leaves
    // the PQC sig in place.
    if (has_any(flags, Flag::HasPqcSig)) {
        out.push_back(p.pqc_sig_type);
        write_u32_le(out, static_cast<std::uint32_t>(p.pqc_sig.size()));
        out.insert(out.end(), p.pqc_sig.begin(), p.pqc_sig.end());
    }

    if (has_any(flags, Flag::HasSig)) {
        out.insert(out.end(), p.signature->begin(), p.signature->end());
    }

    return out;
}

[[nodiscard]] Result<Packet> deserialize(BytesView in) {
    Packet      p;
    std::size_t off = 0;

    // Cursor advancement with overflow + bound + DoS protection.
    const auto need = [&](std::size_t n) -> Status {
        if (n > SIZE_MAX - off) {
            return err(ErrorCode::PacketTruncated, "packet size overflow detected");
        }
        if (off + n > in.size()) {
            return err(ErrorCode::PacketTruncated, "truncated packet detected");
        }
        if (n > MAX_PACKET_SIZE) {
            return err(ErrorCode::PacketFieldOversized,
                       "packet size exceeds maximum allowed");
        }
        return ok();
    };

    // Checked read: bounds-verify then copy @p n bytes into @p dst.
    const auto get = [&](void* dst, std::size_t n) -> Status {
        if (auto s = need(n); !s) {
            return s;
        }
        std::memcpy(dst, in.data() + off, n);
        off += n;
        return ok();
    };

    // Unchecked read — only valid inside a region already covered by a
    // prior need() over the fixed-size prefix.
    const auto take = [&](void* dst, std::size_t n) {
        std::memcpy(dst, in.data() + off, n);
        off += n;
    };

    // Fixed-prefix sanity: header (1+1+4+pk+nonce+8) and length-prefix
    // pair (4+4) must all fit. The trailing length fields are read out
    // of order below — this just bounds the whole header in one check,
    // which also licenses the unchecked take() reads of the fixed
    // fields (70 bytes consumed against a 78-byte bound).
    if (auto s = need(1 + 1 + 4
                      + crypto_kx_PUBLICKEYBYTES
                      + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
                      + 8 + 4 + 4); !s) {
        return std::unexpected{s.error()};
    }

    take(&p.version, 1);
    take(&p.flags, 1);

    std::uint8_t tmp4[4];
    take(tmp4, 4);
    p.rotation_id = read_u32_le(tmp4);

    take(p.eph_pk.data(), p.eph_pk.size());
    take(p.nonce.data(), p.nonce.size());

    std::uint8_t tmp8[8];
    take(tmp8, 8);
    p.counter = read_u64_le(tmp8);

    const Flag flags = flag_from_byte(p.flags);

    if (has_any(flags, Flag::HasRatchet)) {
        std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES> rpk{};
        if (auto s = get(rpk.data(), rpk.size()); !s) {
            return std::unexpected{s.error()};
        }
        p.ratchet_pk = rpk;
    }

    if (has_any(flags, Flag::HasPqcKem)) {
        if (auto s = get(&p.pqc_kem_type, 1); !s) {
            return std::unexpected{s.error()};
        }
        if (auto s = get(tmp4, 4); !s) {
            return std::unexpected{s.error()};
        }
        const std::uint32_t kem_ct_len = read_u32_le(tmp4);
        if (kem_ct_len == 0 || kem_ct_len > MAX_PQC_KEM_CT_SIZE) {
            return err(ErrorCode::PacketFieldOversized,
                       "pqc kem ct size out of bounds");
        }
        p.pqc_kem_ct.resize(kem_ct_len);
        if (auto s = get(p.pqc_kem_ct.data(), kem_ct_len); !s) {
            return std::unexpected{s.error()};
        }
    }

    if (auto s = get(tmp4, 4); !s) {
        return std::unexpected{s.error()};
    }
    const std::uint32_t aad_len = read_u32_le(tmp4);
    if (auto s = get(tmp4, 4); !s) {
        return std::unexpected{s.error()};
    }
    const std::uint32_t ct_len = read_u32_le(tmp4);

    if (p.version != VERSION) {
        return err(ErrorCode::PacketUnknownVersion, "unsupported version");
    }
    if (aad_len > MAX_AAD_SIZE) {
        return err(ErrorCode::PacketFieldOversized,
                   "AAD size exceeds maximum allowed");
    }
    if (ct_len > MAX_CIPHERTEXT_SIZE) {
        return err(ErrorCode::PacketFieldOversized,
                   "ciphertext size exceeds maximum allowed");
    }

    if (aad_len) {
        p.aad.resize(aad_len);
        if (auto s = get(p.aad.data(), aad_len); !s) {
            return std::unexpected{s.error()};
        }
    }
    if (ct_len) {
        p.ciphertext.resize(ct_len);
        if (auto s = get(p.ciphertext.data(), ct_len); !s) {
            return std::unexpected{s.error()};
        }
    }

    // Mirror serialize()'s ordering: PQC sig block before classical sig.
    if (has_any(flags, Flag::HasPqcSig)) {
        if (auto s = get(&p.pqc_sig_type, 1); !s) {
            return std::unexpected{s.error()};
        }
        if (auto s = get(tmp4, 4); !s) {
            return std::unexpected{s.error()};
        }
        const std::uint32_t sig_len = read_u32_le(tmp4);
        if (sig_len == 0 || sig_len > MAX_PQC_SIG_SIZE) {
            return err(ErrorCode::PacketFieldOversized,
                       "pqc sig size out of bounds");
        }
        p.pqc_sig.resize(sig_len);
        if (auto s = get(p.pqc_sig.data(), sig_len); !s) {
            return std::unexpected{s.error()};
        }
    }

    if (has_any(flags, Flag::HasSig)) {
        std::array<std::uint8_t, crypto_sign_BYTES> sig{};
        if (auto s = get(sig.data(), sig.size()); !s) {
            return std::unexpected{s.error()};
        }
        p.signature = sig;
    }

    if (off != in.size()) {
        return err(ErrorCode::PacketTrailingBytes, "trailing bytes in packet");
    }

    return p;
}

}  // namespace nocturne
