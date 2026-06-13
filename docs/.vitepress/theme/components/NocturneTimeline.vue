<script setup lang="ts">
/* --------------------------------------------------------------------------
   NocturneTimeline, a bespoke horizontal timeline contrasting the
   post-quantum standards roadmap with the projected quantum-threat
   trajectory.

   Layout: gradient axis runs left-to-right with year ticks and a
   traveling pulse. Standards events float above the axis; quantum-
   threat events float below. Each card hangs off its tick via a
   dotted SVG connector. Cards fade-up in stagger when the
   IntersectionObserver fires.

   Theme-adaptive via CSS variables; no colour hard-coded outside the
   :root / .dark blocks.
   -------------------------------------------------------------------------- */
import { computed, onMounted, onUnmounted, ref } from 'vue'

interface EventItem {
  year: string
  pos: number              // 0..1 along the axis
  side: 'top' | 'bottom'
  title: string
  bullets: string[]
  badge?: string
}

const events: EventItem[] = [
  { year: '2024', pos: 0.05, side: 'top',    title: 'NIST ratifies the standards',
    bullets: ['FIPS 203, ML-KEM', 'FIPS 204, ML-DSA'], badge: 'Standard' },
  { year: '2025', pos: 0.22, side: 'top',    title: 'Nocturne-KX v4 ships hybrid KEM',
    bullets: ['X25519 ⊕ ML-KEM-1024 default', 'Patent application filed'], badge: 'Release' },
  { year: '2026', pos: 0.40, side: 'top',    title: 'Hybrid signature path lands',
    bullets: ['Ed25519 ⊕ ML-DSA-87', 'PKCS#11 v2.40 validated on SoftHSM2'], badge: 'Release' },
  { year: '2026', pos: 0.50, side: 'bottom', title: 'Today',
    bullets: ['No cryptographically-relevant quantum computer exists', 'Hybrid mode is pure defence-in-depth'], badge: 'Snapshot' },
  { year: '2030', pos: 0.66, side: 'bottom', title: '"Harvest now, decrypt later" window narrows',
    bullets: ['Archived classical ciphertexts at growing risk', 'Standards-only stacks already legacy'], badge: 'Forecast' },
  { year: '2032', pos: 0.83, side: 'bottom', title: 'Plausible CRQC online',
    bullets: ['Shor against X25519 feasible', 'Classical signatures forgeable post-hoc'], badge: 'Forecast' },
  { year: '2035', pos: 0.96, side: 'bottom', title: 'Classical-only stacks retroactively decryptable',
    bullets: ['Any ciphertext archived without PQC defence is open', 'The window we built Nocturne-KX for'], badge: 'Endgame' }
]

const ticks = ['2024', '2025', '2026', '2030', '2032', '2035']
const tickPositions = computed(() => [0.05, 0.22, 0.46, 0.66, 0.83, 0.96])

const rootRef = ref<HTMLElement | null>(null)
const visible = ref(false)

onMounted(() => {
  if (!rootRef.value) return
  const io = new IntersectionObserver(entries => {
    for (const e of entries) if (e.isIntersecting) visible.value = true
  }, { threshold: 0.18 })
  io.observe(rootRef.value)
  onUnmounted(() => io.disconnect())
})

const top    = computed(() => events.filter(e => e.side === 'top'))
const bottom = computed(() => events.filter(e => e.side === 'bottom'))
</script>

<template>
  <section ref="rootRef" class="nx-tl" :class="{ 'is-visible': visible }" aria-label="Post-quantum timeline">
    <header class="nx-tl__heading">
      <span class="nx-tl__pill nx-tl__pill--standards">Standards</span>
      <span class="nx-tl__vs">vs.</span>
      <span class="nx-tl__pill nx-tl__pill--threat">Quantum threat</span>
    </header>

    <div class="nx-tl__viewport">
      <!-- Top row: standards -->
      <div class="nx-tl__row nx-tl__row--top">
        <article
          v-for="(e, i) in top"
          :key="`t-${i}`"
          class="nx-tl__card nx-tl__card--standards"
          :style="{ left: `${e.pos * 100}%`, '--idx': i }"
        >
          <span v-if="e.badge" class="nx-tl__badge">{{ e.badge }}</span>
          <h4 class="nx-tl__card-title">{{ e.title }}</h4>
          <ul class="nx-tl__card-bullets">
            <li v-for="b in e.bullets" :key="b">{{ b }}</li>
          </ul>
          <span class="nx-tl__connector nx-tl__connector--down" />
        </article>
      </div>

      <!-- Axis -->
      <div class="nx-tl__axis">
        <svg class="nx-tl__axis-svg" viewBox="0 0 1000 14" preserveAspectRatio="none">
          <defs>
            <linearGradient id="nx-tl-grad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0"   stop-color="var(--nx-tl-grad-a)" />
              <stop offset="0.5" stop-color="var(--nx-tl-grad-b)" />
              <stop offset="1"   stop-color="var(--nx-tl-grad-c)" />
            </linearGradient>
          </defs>
          <line x1="0" y1="7" x2="1000" y2="7"
                stroke="url(#nx-tl-grad)" stroke-width="2"
                stroke-dasharray="3 7" stroke-linecap="round" />
        </svg>

        <!-- Year ticks -->
        <div
          v-for="(t, i) in ticks"
          :key="t + i"
          class="nx-tl__tick"
          :style="{ left: `${tickPositions[i] * 100}%`, '--tick-delay': `${0.25 + i * 0.07}s` }"
        >
          <span class="nx-tl__tick-dot" />
          <span class="nx-tl__tick-label">{{ t }}</span>
        </div>

        <!-- Traveling pulse -->
        <span class="nx-tl__pulse" />
      </div>

      <!-- Bottom row: quantum threat -->
      <div class="nx-tl__row nx-tl__row--bottom">
        <article
          v-for="(e, i) in bottom"
          :key="`b-${i}`"
          class="nx-tl__card nx-tl__card--threat"
          :style="{ left: `${e.pos * 100}%`, '--idx': i }"
        >
          <span class="nx-tl__connector nx-tl__connector--up" />
          <span v-if="e.badge" class="nx-tl__badge">{{ e.badge }}</span>
          <h4 class="nx-tl__card-title">{{ e.title }}</h4>
          <ul class="nx-tl__card-bullets">
            <li v-for="b in e.bullets" :key="b">{{ b }}</li>
          </ul>
        </article>
      </div>
    </div>
  </section>
</template>

<style scoped>
.nx-tl {
  position: relative;
  margin: 36px 0 40px;
  padding: 32px 24px 28px;
  border-radius: 18px;
  background: var(--nx-tl-bg);
  border: 1px solid var(--nx-tl-border);
  overflow: hidden;
  opacity: 0;
  transform: translateY(14px);
  transition: opacity 600ms cubic-bezier(0.16, 1, 0.3, 1),
              transform 600ms cubic-bezier(0.16, 1, 0.3, 1);
}
.nx-tl.is-visible {
  opacity: 1;
  transform: translateY(0);
}

/* Theme variables ----------------------------------------------------- */
:root:not(.dark) {
  --nx-tl-bg:      linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
  --nx-tl-border:  rgba(15, 23, 42, 0.08);
  --nx-tl-card-bg: #ffffff;
  --nx-tl-card-border: rgba(15, 23, 42, 0.08);
  --nx-tl-card-shadow: 0 12px 30px -16px rgba(15, 23, 42, 0.18);
  --nx-tl-title: #0f172a;
  --nx-tl-text:  #475569;

  --nx-tl-standards-accent: #0e7490;
  --nx-tl-standards-tint:   rgba(34, 211, 238, 0.10);
  --nx-tl-standards-stroke: rgba(8, 145, 178, 0.45);

  --nx-tl-threat-accent: #9f1239;
  --nx-tl-threat-tint:   rgba(244, 63, 94, 0.10);
  --nx-tl-threat-stroke: rgba(190, 18, 60, 0.40);

  --nx-tl-grad-a: rgba(8, 145, 178, 0.7);
  --nx-tl-grad-b: rgba(126, 34, 206, 0.8);
  --nx-tl-grad-c: rgba(190, 18, 60, 0.7);

  --nx-tl-tick-stroke: rgba(15, 23, 42, 0.25);
  --nx-tl-connector:   rgba(15, 23, 42, 0.18);
  --nx-tl-pulse:       rgba(168, 85, 247, 0.55);
}

.dark {
  --nx-tl-bg:      linear-gradient(180deg, #0d0e15 0%, #11121a 100%);
  --nx-tl-border:  rgba(148, 163, 184, 0.10);
  --nx-tl-card-bg: rgba(22, 24, 38, 0.85);
  --nx-tl-card-border: rgba(148, 163, 184, 0.12);
  --nx-tl-card-shadow: 0 14px 38px -18px rgba(0, 0, 0, 0.6);
  --nx-tl-title: #f1f5f9;
  --nx-tl-text:  #cbd5e1;

  --nx-tl-standards-accent: #67e8f9;
  --nx-tl-standards-tint:   rgba(34, 211, 238, 0.10);
  --nx-tl-standards-stroke: rgba(34, 211, 238, 0.30);

  --nx-tl-threat-accent: #fda4af;
  --nx-tl-threat-tint:   rgba(244, 63, 94, 0.10);
  --nx-tl-threat-stroke: rgba(244, 63, 94, 0.32);

  --nx-tl-grad-a: rgba(103, 232, 249, 0.75);
  --nx-tl-grad-b: rgba(192, 132, 252, 0.85);
  --nx-tl-grad-c: rgba(253, 164, 175, 0.75);

  --nx-tl-tick-stroke: rgba(148, 163, 184, 0.40);
  --nx-tl-connector:   rgba(148, 163, 184, 0.28);
  --nx-tl-pulse:       rgba(192, 132, 252, 0.85);
}

/* Heading ------------------------------------------------------------- */
.nx-tl__heading {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 14px;
  margin-bottom: 28px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  letter-spacing: 0.02em;
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
  color: var(--vp-c-text-3);
}

/* Viewport ------------------------------------------------------------ */
.nx-tl__viewport {
  position: relative;
  min-height: 360px;
}

.nx-tl__row {
  position: relative;
  min-height: 150px;
}
.nx-tl__row--top    { padding-bottom: 18px; }
.nx-tl__row--bottom { padding-top: 18px; }

/* Cards --------------------------------------------------------------- */
.nx-tl__card {
  position: absolute;
  width: 230px;
  padding: 14px 16px 12px;
  background: var(--nx-tl-card-bg);
  border: 1px solid var(--nx-tl-card-border);
  border-radius: 12px;
  box-shadow: var(--nx-tl-card-shadow);
  backdrop-filter: blur(8px);
  opacity: 0;
  transform: translate(-50%, 12px);
  animation: nx-tl-card-rise 700ms cubic-bezier(0.22, 1, 0.36, 1) both;
  animation-delay: calc(0.3s + var(--idx, 0) * 0.12s);
  animation-play-state: paused;
}
.nx-tl.is-visible .nx-tl__card {
  animation-play-state: running;
}
.nx-tl__row--top    .nx-tl__card { bottom: 18px; }
.nx-tl__row--bottom .nx-tl__card { top:    18px; }

.nx-tl__card--standards { border-top: 2px solid var(--nx-tl-standards-stroke); }
.nx-tl__card--threat    { border-bottom: 2px solid var(--nx-tl-threat-stroke); }

.nx-tl__card:hover {
  transform: translate(-50%, -2px);
  transition: transform 200ms ease;
}

.nx-tl__badge {
  display: inline-block;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.66rem;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 4px;
  margin-bottom: 6px;
  color: var(--vp-c-text-3);
  background: rgba(148, 163, 184, 0.10);
}
.nx-tl__card--standards .nx-tl__badge {
  color: var(--nx-tl-standards-accent);
  background: var(--nx-tl-standards-tint);
}
.nx-tl__card--threat .nx-tl__badge {
  color: var(--nx-tl-threat-accent);
  background: var(--nx-tl-threat-tint);
}

.nx-tl__card-title {
  font-family: 'Inter', sans-serif;
  font-size: 0.95rem;
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--nx-tl-title);
  margin: 4px 0 8px;
  line-height: 1.25;
}

.nx-tl__card-bullets {
  list-style: none;
  margin: 0;
  padding: 0;
}
.nx-tl__card-bullets li {
  position: relative;
  padding-left: 14px;
  font-size: 0.78rem;
  color: var(--nx-tl-text);
  line-height: 1.45;
  margin-bottom: 4px;
}
.nx-tl__card-bullets li::before {
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

/* Connector from card to axis ---------------------------------------- */
.nx-tl__connector {
  position: absolute;
  left: 50%;
  width: 1px;
  background-image: linear-gradient(var(--nx-tl-connector) 50%, transparent 0);
  background-size: 1px 6px;
  background-repeat: repeat-y;
  transform: translateX(-50%);
}
.nx-tl__connector--down {
  top: 100%;
  height: 28px;
}
.nx-tl__connector--up {
  bottom: 100%;
  height: 28px;
}

/* Axis ---------------------------------------------------------------- */
.nx-tl__axis {
  position: relative;
  height: 36px;
  margin: 4px 0;
  display: flex;
  align-items: center;
}

.nx-tl__axis-svg {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
}

.nx-tl__tick {
  position: absolute;
  top: 0;
  transform: translateX(-50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  opacity: 0;
  animation: nx-tl-tick-pop 0.5s cubic-bezier(0.34, 1.35, 0.64, 1) var(--tick-delay) forwards;
  animation-play-state: paused;
}
.nx-tl.is-visible .nx-tl__tick {
  animation-play-state: running;
}

.nx-tl__tick-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--nx-tl-card-bg);
  border: 2px solid var(--nx-tl-tick-stroke);
  margin-top: 13px;
  box-shadow: 0 0 0 4px var(--nx-tl-bg);
}
.nx-tl__tick-label {
  margin-top: 6px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  color: var(--vp-c-text-3);
  font-weight: 500;
}

/* Traveling pulse */
.nx-tl__pulse {
  position: absolute;
  top: 18px;
  width: 14px;
  height: 14px;
  margin-top: -7px;
  border-radius: 50%;
  background: var(--nx-tl-pulse);
  box-shadow: 0 0 18px 4px var(--nx-tl-pulse);
  animation: nx-tl-pulse-travel 7s linear infinite;
  animation-play-state: paused;
  pointer-events: none;
}
.nx-tl.is-visible .nx-tl__pulse {
  animation-play-state: running;
}

/* Keyframes ---------------------------------------------------------- */
@keyframes nx-tl-card-rise {
  to {
    opacity: 1;
    transform: translate(-50%, 0);
  }
}

@keyframes nx-tl-tick-pop {
  to { opacity: 1; }
}

@keyframes nx-tl-pulse-travel {
  0%   { left: 0%;   opacity: 0; }
  6%   { opacity: 1; }
  94%  { opacity: 1; }
  100% { left: 100%; opacity: 0; }
}

/* Responsive: stack cards on narrow screens -------------------------- */
@media (max-width: 920px) {
  .nx-tl__viewport { min-height: auto; }
  .nx-tl__row { min-height: auto; }
  .nx-tl__card {
    position: relative;
    width: 100%;
    left: 0 !important;
    margin: 12px 0;
    transform: none;
    animation: nx-tl-card-rise-stack 600ms cubic-bezier(0.22, 1, 0.36, 1) both;
    animation-delay: calc(0.2s + var(--idx, 0) * 0.08s);
    animation-play-state: paused;
  }
  .nx-tl.is-visible .nx-tl__card { animation-play-state: running; }
  @keyframes nx-tl-card-rise-stack {
    from { opacity: 0; transform: translateY(12px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .nx-tl__connector { display: none; }
  .nx-tl__axis { margin: 18px 0; }
}

@media (prefers-reduced-motion: reduce) {
  .nx-tl,
  .nx-tl__card,
  .nx-tl__tick,
  .nx-tl__pulse {
    animation: none !important;
    opacity: 1 !important;
    transform: translateX(-50%) !important;
  }
  .nx-tl__pulse { display: none; }
}
</style>
