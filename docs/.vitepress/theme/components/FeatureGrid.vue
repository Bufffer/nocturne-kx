<script setup lang="ts">
/* --------------------------------------------------------------------------
   FeatureGrid, 6-tile capability matrix sitting below the hero.
   Each tile lists a primitive + a one-line justification + an anchor.
   -------------------------------------------------------------------------- */

interface Feature {
  title: string
  body: string
  href: string
  iconPath: string
  accent: 'cyan' | 'violet' | 'rose'
}

const features: Feature[] = [
  {
    title: 'Hybrid post-quantum KEM',
    body: 'X25519 ⊕ ML-KEM-1024 with NIST SP 800-56C combiner. Defence-in-depth: an attacker must break both.',
    href: './pqc/kem',
    iconPath:
      'M12 2 4 6v6c0 5 3.5 9.5 8 10 4.5-.5 8-5 8-10V6l-8-4Z',
    accent: 'cyan'
  },
  {
    title: 'Bidirectional replay protection',
    body: 'Prefix-based counter separation on a MAC-protected on-disk DB.',
    href: './guide/replay',
    iconPath:
      'M3 12a9 9 0 1 0 3.5-7.1M3 4v6h6',
    accent: 'violet'
  },
  {
    title: 'PKCS#11 HSM integration',
    body: 'Production-grade adapter, Thales, Utimaco, YubiHSM2, AWS CloudHSM, SoftHSM2. CKM_EDDSA + session pool.',
    href: './guide/hsm',
    iconPath:
      'M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z',
    accent: 'cyan'
  },
  {
    title: 'Hash-chained audit log',
    body: 'BLAKE2b chain + per-record Ed25519 signatures + optional WORM directory. verify_chain replays the whole history.',
    href: './guide/audit',
    iconPath:
      'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Zm0 0v6h6M9 13h6M9 17h6',
    accent: 'rose'
  },
  {
    title: 'Side-channel mitigations',
    body: 'sodium_memcmp + sodium_memzero + 100-500µs random delays + clflush + branchless ct_select.',
    href: './architecture',
    iconPath:
      'M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83',
    accent: 'violet'
  },
  {
    title: 'Single binary, no GC',
    body: 'C++23, libsodium, optional liboqs. Static or dynamic. ENABLE_HARDENING for hardened Docker builds.',
    href: './guide/quickstart',
    iconPath:
      'M20 17l-8-4-8 4M20 17l-8 4-8-4M20 17V7l-8-4-8 4v10M12 13V3',
    accent: 'cyan'
  }
]
</script>

<template>
  <section class="nx-features">
    <header class="nx-features__header">
      <h2 class="nx-features__title">
        Six primitives. One binary. Audit-trail by default.
      </h2>
      <p class="nx-features__sub">
        Nocturne-KX folds modern cryptography into the operational shape of a Unix tool.
        text in, ciphertext out, every operation hash-chained.
      </p>
    </header>

    <div class="nx-features__grid">
      <a
        v-for="f in features"
        :key="f.title"
        :href="f.href"
        class="nx-feature"
        :class="`nx-feature--${f.accent}`"
      >
        <div class="nx-feature__icon" aria-hidden="true">
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" stroke-width="1.8"
            stroke-linecap="round" stroke-linejoin="round">
            <path :d="f.iconPath" />
          </svg>
        </div>
        <h3 class="nx-feature__title">{{ f.title }}</h3>
        <p class="nx-feature__body">{{ f.body }}</p>
        <span class="nx-feature__arrow">→</span>
      </a>
    </div>
  </section>
</template>

<style scoped>
.nx-features {
  max-width: 1180px;
  margin: 0 auto;
  padding: 80px 24px;
}

.nx-features__header {
  text-align: center;
  margin-bottom: 56px;
}

.nx-features__title {
  font-size: clamp(1.7rem, 3vw, 2.4rem);
  font-weight: 700;
  letter-spacing: -0.025em;
  line-height: 1.15;
  margin: 0 0 16px;
  color: var(--vp-c-text-1);
}

.nx-features__sub {
  font-size: 1.05rem;
  line-height: 1.6;
  color: var(--vp-c-text-2);
  max-width: 640px;
  margin: 0 auto;
}

.nx-features__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 18px;
}

.nx-feature {
  position: relative;
  display: block;
  padding: 26px 24px 26px;
  border-radius: 14px;
  background: var(--vp-c-bg-elv);
  border: 1px solid var(--vp-c-divider);
  text-decoration: none !important;
  transition: transform 200ms ease, border-color 200ms ease, box-shadow 200ms ease;
  overflow: hidden;
}

.nx-feature::before {
  content: '';
  position: absolute;
  inset: 0;
  background: linear-gradient(135deg, transparent 60%, currentColor 200%);
  opacity: 0;
  transition: opacity 250ms ease;
  pointer-events: none;
}

.nx-feature--cyan { color: var(--nx-cyan); }
.nx-feature--violet { color: var(--nx-violet); }
.nx-feature--rose { color: var(--nx-rose); }

.nx-feature:hover {
  transform: translateY(-3px);
  border-color: currentColor;
  box-shadow: 0 18px 40px -22px currentColor;
}
.nx-feature:hover::before {
  opacity: 0.06;
}

.nx-feature__icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 38px;
  height: 38px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  margin-bottom: 16px;
}
.dark .nx-feature__icon {
  background: rgba(255, 255, 255, 0.03);
}

.nx-feature__title {
  font-size: 1.05rem;
  font-weight: 600;
  margin: 0 0 8px;
  color: var(--vp-c-text-1);
  letter-spacing: -0.01em;
}

.nx-feature__body {
  font-size: 0.92rem;
  line-height: 1.55;
  color: var(--vp-c-text-2);
  margin: 0;
}

.nx-feature__arrow {
  display: inline-block;
  margin-top: 14px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  color: currentColor;
  opacity: 0.7;
  transition: transform 200ms ease, opacity 200ms ease;
}
.nx-feature:hover .nx-feature__arrow {
  transform: translateX(4px);
  opacity: 1;
}
</style>
