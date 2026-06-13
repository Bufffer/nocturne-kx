<script setup lang="ts">
/* --------------------------------------------------------------------------
   NocturneTimeline, v2: a clean two-column vertical timeline.

   Standards cards live on the left, quantum-threat cards on the right,
   with a gradient axis running down the middle. Every row is a single
   year, so cards can never collide horizontally; empty cells just
   stay blank.

   Theme-adaptive via CSS variables (light + dark). Animations gated by
   IntersectionObserver; prefers-reduced-motion shuts every keyframe
   off cleanly.
   -------------------------------------------------------------------------- */
import { onMounted, onUnmounted, ref } from 'vue'

interface Card {
  badge: string
  title: string
  bullets: string[]
}
interface Row {
  year: string
  standards?: Card
  threat?: Card
}

const rows: Row[] = [
  {
    year: '2024',
    standards: {
      badge: 'Standard',
      title: 'NIST ratifies the post-quantum standards',
      bullets: ['FIPS 203 (ML-KEM)', 'FIPS 204 (ML-DSA)']
    }
  },
  {
    year: '2025',
    standards: {
      badge: 'Release',
      title: 'Nocturne-KX v4 ships hybrid KEM',
      bullets: ['X25519 ⊕ ML-KEM-1024 default', 'Patent application filed']
    }
  },
  {
    year: '2026',
    standards: {
      badge: 'Release',
      title: 'Hybrid signature path lands',
      bullets: ['Ed25519 ⊕ ML-DSA-87', 'PKCS#11 v2.40 validated on SoftHSM2']
    },
    threat: {
      badge: 'Snapshot',
      title: 'Today',
      bullets: ['No cryptographically-relevant quantum computer yet', 'Hybrid mode is pure defence-in-depth']
    }
  },
  {
    year: '2030',
    threat: {
      badge: 'Forecast',
      title: '"Harvest now, decrypt later" window narrows',
      bullets: ['Archived classical ciphertexts at growing risk', 'Standards-only stacks already legacy']
    }
  },
  {
    year: '2032',
    threat: {
      badge: 'Forecast',
      title: 'Plausible CRQC online',
      bullets: ['Shor against X25519 feasible', 'Classical signatures forgeable post-hoc']
    }
  },
  {
    year: '2035',
    threat: {
      badge: 'Endgame',
      title: 'Classical-only stacks retroactively decryptable',
      bullets: ['Any ciphertext archived without PQC defence is open', 'The window we built Nocturne-KX for']
    }
  }
]

const rootRef = ref<HTMLElement | null>(null)
const visible = ref(false)

onMounted(() => {
  if (!rootRef.value) return
  const io = new IntersectionObserver(entries => {
    for (const e of entries) if (e.isIntersecting) visible.value = true
  }, { threshold: 0.15 })
  io.observe(rootRef.value)
  onUnmounted(() => io.disconnect())
})
</script>

<template>
  <section ref="rootRef" class="nx-tl" :class="{ 'is-visible': visible }" aria-label="Post-quantum timeline">
    <header class="nx-tl__head">
      <span class="nx-tl__pill nx-tl__pill--standards">Standards</span>
      <span class="nx-tl__vs">vs.</span>
      <span class="nx-tl__pill nx-tl__pill--threat">Quantum threat</span>
    </header>

    <div class="nx-tl__grid">
      <!-- Column headers -->
      <div class="nx-tl__col-head nx-tl__col-head--left">Standards</div>
      <div class="nx-tl__col-head nx-tl__col-head--year">Year</div>
      <div class="nx-tl__col-head nx-tl__col-head--right">Quantum threat</div>

      <template v-for="(r, i) in rows" :key="r.year + i">
        <!-- Left card slot -->
        <div class="nx-tl__cell nx-tl__cell--left" :style="{ '--idx': i }">
          <article v-if="r.standards" class="nx-tl__card nx-tl__card--standards">
            <span class="nx-tl__badge nx-tl__badge--standards">{{ r.standards.badge }}</span>
            <h4 class="nx-tl__title">{{ r.standards.title }}</h4>
            <ul class="nx-tl__bullets">
              <li v-for="b in r.standards.bullets" :key="b">{{ b }}</li>
            </ul>
            <span class="nx-tl__arm nx-tl__arm--right" />
          </article>
        </div>

        <!-- Centre year node -->
        <div class="nx-tl__cell nx-tl__cell--year" :style="{ '--idx': i }">
          <span class="nx-tl__node" />
          <span class="nx-tl__year">{{ r.year }}</span>
        </div>

        <!-- Right card slot -->
        <div class="nx-tl__cell nx-tl__cell--right" :style="{ '--idx': i }">
          <article v-if="r.threat" class="nx-tl__card nx-tl__card--threat">
            <span class="nx-tl__arm nx-tl__arm--left" />
            <span class="nx-tl__badge nx-tl__badge--threat">{{ r.threat.badge }}</span>
            <h4 class="nx-tl__title">{{ r.threat.title }}</h4>
            <ul class="nx-tl__bullets">
              <li v-for="b in r.threat.bullets" :key="b">{{ b }}</li>
            </ul>
          </article>
        </div>
      </template>

      <!-- Axis line + traveling pulse -->
      <div class="nx-tl__axis" aria-hidden="true">
        <span class="nx-tl__axis-line" />
        <span class="nx-tl__pulse" />
      </div>
    </div>
  </section>
</template>

<style scoped>
.nx-tl {
  position: relative;
  margin: 36px 0 40px;
  padding: 26px 24px 28px;
  border-radius: 18px;
  background: var(--nx-tl-bg);
  border: 1px solid var(--nx-tl-border);
  opacity: 0;
  transform: translateY(14px);
  transition: opacity 600ms cubic-bezier(0.16, 1, 0.3, 1),
              transform 600ms cubic-bezier(0.16, 1, 0.3, 1);
}
.nx-tl.is-visible {
  opacity: 1;
  transform: translateY(0);
}

/* ----- Theme variables ----- */
:root:not(.dark) {
  --nx-tl-bg:      linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
  --nx-tl-border:  rgba(15, 23, 42, 0.08);
  --nx-tl-card-bg: #ffffff;
  --nx-tl-card-border: rgba(15, 23, 42, 0.08);
  --nx-tl-card-shadow: 0 10px 30px -16px rgba(15, 23, 42, 0.20);
  --nx-tl-title: #0f172a;
  --nx-tl-text:  #475569;
  --nx-tl-muted: #94a3b8;

  --nx-tl-standards-accent: #0e7490;
  --nx-tl-standards-tint:   rgba(34, 211, 238, 0.12);
  --nx-tl-standards-stroke: rgba(8, 145, 178, 0.40);

  --nx-tl-threat-accent: #9f1239;
  --nx-tl-threat-tint:   rgba(244, 63, 94, 0.12);
  --nx-tl-threat-stroke: rgba(190, 18, 60, 0.35);

  --nx-tl-axis-grad: linear-gradient(180deg,
    rgba(8, 145, 178, 0.55) 0%,
    rgba(126, 34, 206, 0.6) 50%,
    rgba(190, 18, 60, 0.55) 100%
  );
  --nx-tl-axis-bg: rgba(15, 23, 42, 0.10);

  --nx-tl-node-bg: #ffffff;
  --nx-tl-node-stroke: rgba(126, 34, 206, 0.55);

  --nx-tl-pulse-color: rgba(168, 85, 247, 0.65);
  --nx-tl-pulse-shadow: rgba(168, 85, 247, 0.45);
}

.dark {
  --nx-tl-bg:      linear-gradient(180deg, #0d0e15 0%, #11121a 100%);
  --nx-tl-border:  rgba(148, 163, 184, 0.10);
  --nx-tl-card-bg: rgba(22, 24, 38, 0.85);
  --nx-tl-card-border: rgba(148, 163, 184, 0.12);
  --nx-tl-card-shadow: 0 14px 38px -20px rgba(0, 0, 0, 0.55);
  --nx-tl-title: #f1f5f9;
  --nx-tl-text:  #cbd5e1;
  --nx-tl-muted: #64748b;

  --nx-tl-standards-accent: #67e8f9;
  --nx-tl-standards-tint:   rgba(34, 211, 238, 0.10);
  --nx-tl-standards-stroke: rgba(34, 211, 238, 0.32);

  --nx-tl-threat-accent: #fda4af;
  --nx-tl-threat-tint:   rgba(244, 63, 94, 0.10);
  --nx-tl-threat-stroke: rgba(244, 63, 94, 0.32);

  --nx-tl-axis-grad: linear-gradient(180deg,
    rgba(103, 232, 249, 0.7) 0%,
    rgba(192, 132, 252, 0.8) 50%,
    rgba(253, 164, 175, 0.7) 100%
  );
  --nx-tl-axis-bg: rgba(148, 163, 184, 0.18);

  --nx-tl-node-bg: #11121a;
  --nx-tl-node-stroke: rgba(192, 132, 252, 0.65);

  --nx-tl-pulse-color: rgba(192, 132, 252, 0.85);
  --nx-tl-pulse-shadow: rgba(192, 132, 252, 0.55);
}

/* ----- Heading ----- */
.nx-tl__head {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 14px;
  margin-bottom: 22px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
}
.nx-tl__pill {
  padding: 4px 12px;
  border-radius: 999px;
  font-weight: 500;
}
.nx-tl__pill--standards {
  color: var(--nx-tl-standards-accent);
  background: var(--nx-tl-standards-tint);
  border: 1px solid var(--nx-tl-standards-stroke);
}
.nx-tl__pill--threat {
  color: var(--nx-tl-threat-accent);
  background: var(--nx-tl-threat-tint);
  border: 1px solid var(--nx-tl-threat-stroke);
}
.nx-tl__vs {
  color: var(--nx-tl-muted);
}

/* ----- Grid layout: card | axis | card ----- */
.nx-tl__grid {
  position: relative;
  display: grid;
  grid-template-columns: 1fr 110px 1fr;
  row-gap: 32px;
  column-gap: 0;
  align-items: stretch;
}

.nx-tl__col-head {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--nx-tl-muted);
  padding: 0 12px 14px;
  border-bottom: 1px dashed var(--nx-tl-card-border);
}
.nx-tl__col-head--left  { text-align: right;  padding-right: 28px; color: var(--nx-tl-standards-accent); }
.nx-tl__col-head--year  { text-align: center; }
.nx-tl__col-head--right { text-align: left;   padding-left: 28px; color: var(--nx-tl-threat-accent); }

/* ----- Cells ----- */
.nx-tl__cell {
  display: flex;
  align-items: center;
  min-height: 92px;
}
.nx-tl__cell--left  { justify-content: flex-end;   padding-right: 28px; }
.nx-tl__cell--right { justify-content: flex-start; padding-left:  28px; }
.nx-tl__cell--year  {
  justify-content: center;
  flex-direction: column;
  gap: 6px;
  position: relative;
  z-index: 2;
}

/* ----- Axis line behind the centre column ----- */
.nx-tl__axis {
  position: absolute;
  top: 50px;
  bottom: 0;
  left: 50%;
  width: 2px;
  transform: translateX(-50%);
  z-index: 1;
}
.nx-tl__axis-line {
  position: absolute;
  inset: 0;
  background: var(--nx-tl-axis-grad);
  opacity: 0.65;
  border-radius: 999px;
}
.nx-tl__pulse {
  position: absolute;
  left: 50%;
  top: 0;
  width: 12px;
  height: 12px;
  margin-left: -6px;
  border-radius: 50%;
  background: var(--nx-tl-pulse-color);
  box-shadow: 0 0 18px 4px var(--nx-tl-pulse-shadow);
  animation: nx-tl-pulse 6s cubic-bezier(0.6, 0, 0.4, 1) infinite;
  animation-play-state: paused;
}
.nx-tl.is-visible .nx-tl__pulse {
  animation-play-state: running;
}

/* ----- Year nodes ----- */
.nx-tl__node {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: var(--nx-tl-node-bg);
  border: 2px solid var(--nx-tl-node-stroke);
  box-shadow: 0 0 0 4px var(--nx-tl-bg, transparent);
  opacity: 0;
  transform: scale(0.5);
  animation: nx-tl-node-pop 0.55s cubic-bezier(0.34, 1.35, 0.64, 1) both;
  animation-delay: calc(0.25s + var(--idx, 0) * 0.10s);
  animation-play-state: paused;
}
.nx-tl.is-visible .nx-tl__node {
  animation-play-state: running;
}

.nx-tl__year {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--nx-tl-title);
  letter-spacing: -0.005em;
}

/* ----- Cards ----- */
.nx-tl__card {
  position: relative;
  width: 100%;
  max-width: 360px;
  padding: 14px 16px 12px;
  background: var(--nx-tl-card-bg);
  border: 1px solid var(--nx-tl-card-border);
  border-radius: 12px;
  box-shadow: var(--nx-tl-card-shadow);
  backdrop-filter: blur(8px);
  opacity: 0;
  animation-fill-mode: both;
  animation-duration: 700ms;
  animation-timing-function: cubic-bezier(0.22, 1, 0.36, 1);
  animation-delay: calc(0.35s + var(--idx, 0) * 0.12s);
  animation-play-state: paused;
}
.nx-tl.is-visible .nx-tl__card {
  animation-play-state: running;
}

.nx-tl__card--standards {
  border-left: 3px solid var(--nx-tl-standards-stroke);
  animation-name: nx-tl-card-slide-right;
}
.nx-tl__card--threat {
  border-right: 3px solid var(--nx-tl-threat-stroke);
  animation-name: nx-tl-card-slide-left;
}

.nx-tl__card:hover {
  transform: translateY(-2px);
  transition: transform 200ms ease;
}

/* Horizontal connector arm from card to axis */
.nx-tl__arm {
  position: absolute;
  top: 50%;
  width: 22px;
  height: 1px;
  background-image: linear-gradient(90deg,
    var(--nx-tl-card-border) 0,
    var(--nx-tl-card-border) 60%,
    transparent 60%);
  background-size: 6px 1px;
  background-repeat: repeat-x;
}
.nx-tl__arm--right { right: -22px; }
.nx-tl__arm--left  { left:  -22px; }

.nx-tl__badge {
  display: inline-block;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.66rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 4px;
  margin-bottom: 6px;
  font-weight: 500;
}
.nx-tl__badge--standards {
  color: var(--nx-tl-standards-accent);
  background: var(--nx-tl-standards-tint);
}
.nx-tl__badge--threat {
  color: var(--nx-tl-threat-accent);
  background: var(--nx-tl-threat-tint);
}

.nx-tl__title {
  font-family: 'Inter', sans-serif;
  font-size: 0.98rem;
  font-weight: 600;
  letter-spacing: -0.012em;
  color: var(--nx-tl-title);
  margin: 4px 0 8px;
  line-height: 1.30;
}

.nx-tl__bullets {
  list-style: none;
  margin: 0;
  padding: 0;
}
.nx-tl__bullets li {
  position: relative;
  padding-left: 14px;
  font-size: 0.82rem;
  color: var(--nx-tl-text);
  line-height: 1.5;
  margin-bottom: 4px;
}
.nx-tl__bullets li::before {
  content: '';
  position: absolute;
  left: 2px;
  top: 9px;
  width: 4px;
  height: 4px;
  border-radius: 50%;
  background: currentColor;
  opacity: 0.55;
}

/* ----- Keyframes ----- */
@keyframes nx-tl-card-slide-right {
  from { opacity: 0; transform: translateX(20px); }
  to   { opacity: 1; transform: translateX(0); }
}
@keyframes nx-tl-card-slide-left {
  from { opacity: 0; transform: translateX(-20px); }
  to   { opacity: 1; transform: translateX(0); }
}
@keyframes nx-tl-node-pop {
  0%   { opacity: 0; transform: scale(0.4); }
  60%  { opacity: 1; transform: scale(1.15); }
  100% { opacity: 1; transform: scale(1); }
}
@keyframes nx-tl-pulse {
  0%   { top: 0%;    opacity: 0; }
  5%   { opacity: 1; }
  95%  { opacity: 1; }
  100% { top: 100%;  opacity: 0; }
}

/* ----- Mobile ----- */
@media (max-width: 720px) {
  .nx-tl__grid {
    grid-template-columns: 60px 1fr;
    row-gap: 18px;
  }
  .nx-tl__col-head { display: none; }
  .nx-tl__cell--left {
    display: none;
  }
  .nx-tl__cell--left .nx-tl__card {
    display: block;
  }
  /* On mobile: collapse to single column. Year on left, all cards on right. */
  .nx-tl__cell--year  { order: 1; justify-content: center; padding: 0; min-height: 0; }
  .nx-tl__cell--right { order: 2; padding-left: 14px; }
  .nx-tl__cell--left  {
    display: flex;
    order: 2;
    grid-column: 2;
    justify-content: flex-start;
    padding-left: 14px;
  }
  .nx-tl__arm { display: none; }
  .nx-tl__card { max-width: 100%; }
  .nx-tl__axis {
    left: 30px;
    transform: none;
  }
}

@media (prefers-reduced-motion: reduce) {
  .nx-tl,
  .nx-tl__card,
  .nx-tl__node,
  .nx-tl__pulse {
    animation: none !important;
    opacity: 1 !important;
    transform: none !important;
  }
  .nx-tl__pulse { display: none; }
}
</style>
