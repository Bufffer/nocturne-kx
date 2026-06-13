<script setup lang="ts">
/* --------------------------------------------------------------------------
   WireFormat — interactive visualisation of the Nocturne-KX v3 packet
   layout. Hover a field to surface its description; click to deep-link
   into the architecture page. The byte ribbons are drawn from a
   declarative spec so adding a future version is a single data change.
   -------------------------------------------------------------------------- */
import { ref } from 'vue'

interface Field {
  name: string
  size: string
  description: string
  optional?: boolean
  group: 'header' | 'kem' | 'aead' | 'sig'
}

const fields: Field[] = [
  { name: 'ver',       size: '1 B',  description: 'Packet version (=3). Bumped on incompatible wire changes.', group: 'header' },
  { name: 'flags',     size: '1 B',  description: 'Bit set: HAS_SIG (0x01), HAS_RATCHET (0x02), HAS_PQC_KEM (0x04), HAS_PQC_SIG (0x08).', group: 'header' },
  { name: 'rotation_id', size: '4 B', description: 'Key-rotation counter; receiver rejects packets below --min-rotation.', group: 'header' },
  { name: 'eph_pk',    size: '32 B', description: 'X25519 ephemeral public key. Zeroed when HAS_PQC_KEM is set.', group: 'header' },
  { name: 'nonce',     size: '24 B', description: 'XChaCha20-Poly1305 nonce. Derived deterministically per session.', group: 'header' },
  { name: 'counter',   size: '8 B',  description: 'Monotonic per-receiver counter; replay DB enforces strict ordering.', group: 'header' },
  { name: 'ratchet_pk', size: '32 B', description: 'Optional DH-ratchet public key (HAS_RATCHET).', optional: true, group: 'header' },
  { name: 'kem_type',  size: '1 B',  description: 'KEMType byte: HYBRID_X25519_MLKEM1024 (1) or PURE_MLKEM1024 (2).', optional: true, group: 'kem' },
  { name: 'kem_ct_len', size: '4 B', description: 'KEM ciphertext length (1568 for ML-KEM-1024 alone, 1600 for hybrid).', optional: true, group: 'kem' },
  { name: 'kem_ct',    size: '1568–1600 B', description: 'KEM ciphertext. Receiver decapsulates with sk; sender derives via encapsulate.', optional: true, group: 'kem' },
  { name: 'aad_len',   size: '4 B', description: 'Associated-data length (LE u32).', group: 'aead' },
  { name: 'ct_len',    size: '4 B', description: 'AEAD ciphertext length (LE u32).', group: 'aead' },
  { name: 'aad',       size: 'aad_len',  description: 'Associated data — authenticated, not encrypted.', group: 'aead' },
  { name: 'ct',        size: 'ct_len',   description: 'XChaCha20-Poly1305 ciphertext + 16 B Poly1305 tag.', group: 'aead' },
  { name: 'ed25519_sig', size: '64 B', description: 'Optional Ed25519 detached signature (HAS_SIG).', optional: true, group: 'sig' },
  { name: 'pqc_sig_type', size: '1 B', description: 'Optional PQ SigType byte (HAS_PQC_SIG).', optional: true, group: 'sig' },
  { name: 'pqc_sig',   size: '64–8192 B', description: 'Variable-length PQ signature; ML-DSA-87 is 4627 B, hybrid is 4691 B.', optional: true, group: 'sig' }
]

const active = ref<Field | null>(null)

function pick(f: Field) {
  active.value = active.value?.name === f.name ? null : f
}
</script>

<template>
  <div class="nx-wire">
    <div class="nx-wire__diagram">
      <div
        v-for="f in fields"
        :key="f.name"
        class="nx-wire__cell"
        :class="[
          `nx-wire__cell--${f.group}`,
          { 'is-optional': f.optional, 'is-active': active?.name === f.name }
        ]"
        @click="pick(f)"
        @mouseenter="active = f"
        @mouseleave="active = null"
      >
        <div class="nx-wire__cell-name">{{ f.name }}</div>
        <div class="nx-wire__cell-size">{{ f.size }}</div>
      </div>
    </div>

    <div class="nx-wire__legend">
      <span class="nx-wire__chip nx-wire__chip--header">header</span>
      <span class="nx-wire__chip nx-wire__chip--kem">kem (optional)</span>
      <span class="nx-wire__chip nx-wire__chip--aead">aead</span>
      <span class="nx-wire__chip nx-wire__chip--sig">signatures (optional)</span>
    </div>

    <transition name="nx-fade">
      <div v-if="active" class="nx-wire__detail">
        <div class="nx-wire__detail-head">
          <code>{{ active.name }}</code>
          <span class="nx-wire__detail-size">{{ active.size }}</span>
          <span v-if="active.optional" class="nx-badge nx-badge--violet">optional</span>
        </div>
        <p class="nx-wire__detail-body">{{ active.description }}</p>
      </div>
    </transition>
  </div>
</template>

<style scoped>
.nx-wire {
  border: 1px solid var(--vp-c-divider);
  border-radius: 14px;
  background: var(--vp-c-bg-elv);
  padding: 24px;
  margin: 32px 0;
}

.nx-wire__diagram {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.nx-wire__cell {
  flex: 1 1 auto;
  min-width: 96px;
  padding: 12px 12px;
  border-radius: 8px;
  cursor: pointer;
  border: 1px solid transparent;
  transition: transform 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
  text-align: center;
}

.nx-wire__cell:hover { transform: translateY(-2px); }
.nx-wire__cell.is-active {
  transform: translateY(-2px);
  border-color: currentColor;
  box-shadow: 0 10px 24px -12px currentColor;
}

.nx-wire__cell--header { background: rgba(34, 211, 238, 0.10); color: #67e8f9; }
.nx-wire__cell--kem    { background: rgba(168, 85, 247, 0.10); color: #c084fc; }
.nx-wire__cell--aead   { background: rgba(34, 197, 94, 0.10);  color: #86efac; }
.nx-wire__cell--sig    { background: rgba(244, 63, 94, 0.10);  color: #fda4af; }

.nx-wire__cell.is-optional {
  background-image:
    repeating-linear-gradient(
      45deg,
      transparent 0,
      transparent 6px,
      rgba(255, 255, 255, 0.04) 6px,
      rgba(255, 255, 255, 0.04) 12px
    );
}

.nx-wire__cell-name {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  font-weight: 600;
  color: var(--vp-c-text-1);
  letter-spacing: -0.01em;
}
.nx-wire__cell-size {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  margin-top: 4px;
  color: currentColor;
  opacity: 0.85;
}

.nx-wire__legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 20px;
}

.nx-wire__chip {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid currentColor;
}
.nx-wire__chip--header { color: #67e8f9; background: rgba(34, 211, 238, 0.10); }
.nx-wire__chip--kem    { color: #c084fc; background: rgba(168, 85, 247, 0.10); }
.nx-wire__chip--aead   { color: #86efac; background: rgba(34, 197, 94, 0.10); }
.nx-wire__chip--sig    { color: #fda4af; background: rgba(244, 63, 94, 0.10); }

.nx-wire__detail {
  margin-top: 20px;
  padding: 16px 18px;
  border-radius: 10px;
  background: var(--vp-c-bg);
  border: 1px solid var(--vp-c-divider);
}
.nx-wire__detail-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}
.nx-wire__detail-head code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.95rem;
  color: var(--vp-c-text-1);
  background: rgba(34, 211, 238, 0.10);
  padding: 2px 8px;
  border-radius: 4px;
}
.nx-wire__detail-size {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.78rem;
  color: var(--vp-c-text-3);
}
.nx-wire__detail-body {
  font-size: 0.93rem;
  line-height: 1.6;
  color: var(--vp-c-text-2);
  margin: 0;
}

.nx-fade-enter-active, .nx-fade-leave-active { transition: opacity 180ms ease; }
.nx-fade-enter-from, .nx-fade-leave-to { opacity: 0; }
</style>
