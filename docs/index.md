---
layout: home
pageClass: nx-home
title: Nocturne-KX — Post-quantum encryption toolkit
titleTemplate: false

hero:
  name: ''
  text: ''
  tagline: ''

features: []
---

<HeroAnimated />

<FeatureGrid />

<CodeShowcase />

<section class="nx-section nx-section--narrow">

## Wire format <span class="nx-badge nx-badge--violet">v3</span>

Every Nocturne packet is a length-prefixed, version-tagged binary frame.
Hover any field for its role and size; everything optional is hatched.

<WireFormat />

The KEM block is gated by `FLAG_HAS_PQC_KEM`; when present, `eph_pk` is zeroed
and the receiver runs decapsulation against `kem_ct` instead of an X25519 ECDH.
Same packet shape carries every mode — classical X25519, hybrid X25519+ML-KEM-1024,
or pure ML-KEM-1024 — so call sites stay symmetric.

[Read the full wire-format spec →](./guide/wire-format)

</section>

<section class="nx-section nx-section--narrow">

## Why Nocturne-KX exists

Post-quantum cryptography is shipping in 2026 — but most production stacks
still pin to X25519 and Ed25519. The window between "harvest now, decrypt
later" and "lattice-based standards are mandatory" is closing fast.

Nocturne-KX is the answer for teams that need to ship a single binary
*today* that:

- defends against state-level adversaries with a hybrid X25519 ⊕ ML-KEM-1024 KEM (patent pending),
- protects every channel with bidirectional replay detection on a MAC-protected DB (patent pending),
- speaks PKCS#11 v2.40 to real HSMs (Thales, Utimaco, YubiHSM2, AWS CloudHSM, SoftHSM2 for dev),
- hash-chains every operation into a verifiable, Ed25519-signed audit log,
- and never leaves clean-up to the caller — `secure_zero_memory` + `flush_cache_line` + `memory_barrier` are the default.

[Read the threat model →](./guide/threat-model)

</section>

<section class="nx-section">

## Trusted primitives, conservative choices

::: tip Cryptographic stack
**Classical:** X25519 ECDH (RFC 7748), Ed25519 (RFC 8032), XChaCha20-Poly1305 (RFC 8439), BLAKE2b, Argon2id.
**Post-quantum:** ML-KEM-1024 (NIST FIPS 203, Level 5), ML-DSA-87 (NIST FIPS 204, Level 5) via liboqs.
**Combiner:** NIST SP 800-56C Revision 2 KDF with explicit domain separation per protocol version.
:::

::: warning Operational defaults
**Replay:** strict monotonic counter; same-counter packets rejected.
**Rotation:** `--min-rotation` floor on receiver; stale keys are not silently accepted.
**Audit:** every CLI invocation writes a JSONL record; chain head is computable in O(records).
**HSM:** keys never leave the device in plaintext (FIPS 140-3 path); FileHSM exists only for dev.
:::

</section>

<style>
.nx-home .VPHome {
  padding-bottom: 0 !important;
}
.nx-home .VPHome > .VPHero,
.nx-home .VPHome > .VPFeatures {
  display: none;
}
.nx-section {
  max-width: 1180px;
  margin: 0 auto;
  padding: 70px 24px;
  border-top: 1px solid var(--vp-c-divider);
}
.nx-section--narrow {
  max-width: 880px;
}
.nx-section h2 {
  font-size: clamp(1.6rem, 2.8vw, 2.2rem);
  font-weight: 700;
  letter-spacing: -0.025em;
  margin-bottom: 18px;
  color: var(--vp-c-text-1);
  display: flex;
  align-items: center;
  gap: 12px;
}
.nx-section p {
  font-size: 1.02rem;
  line-height: 1.7;
  color: var(--vp-c-text-2);
}
</style>
