<script setup lang="ts">
/* --------------------------------------------------------------------------
   NocturneArchFlow, the bespoke architecture diagram.

   Built to replicate the Stripe / Linear / Vercel network-diagram
   aesthetic: a constellation of soft node cards orbiting a central
   gradient brand block, connected by dotted SVG paths. Traveling dots
   ride each path so the system feels alive even when idle.

   Everything is theme-adaptive through CSS variables, so the same
   structural drawing works on light and dark backgrounds without
   recolouring at the Vue layer.
   -------------------------------------------------------------------------- */
import { computed, onMounted, onUnmounted, ref } from 'vue'

interface Node {
  id: string
  label: string
  sublabel?: string
  accent: 'cyan' | 'violet' | 'rose' | 'amber'
  /** centre in viewBox coords (0-1200, 0-680) */
  x: number
  y: number
  /** card half-extents */
  w: number
  h: number
}

const VB_W = 1200
const VB_H = 680

const nodes: Node[] = [
  { id: 'sender',   label: 'Sender CLI',        sublabel: 'encrypt · gen-keys', accent: 'cyan',   x: 130,  y: 340, w: 95,  h: 38 },

  { id: 'kem',      label: 'KEM Factory',       sublabel: 'X25519 ⊕ ML-KEM-1024', accent: 'violet', x: 360,  y: 110, w: 115, h: 40 },
  { id: 'sig',      label: 'Signature Factory', sublabel: 'Ed25519 ⊕ ML-DSA-87',  accent: 'violet', x: 600,  y: 70,  w: 120, h: 40 },
  { id: 'aead',     label: 'AEAD',              sublabel: 'XChaCha20-Poly1305',   accent: 'amber',  x: 840,  y: 110, w: 110, h: 40 },

  { id: 'core',     label: 'Nocturne-KX',       sublabel: 'v3 wire · Result<T>', accent: 'cyan',   x: 600,  y: 340, w: 150, h: 60 },

  { id: 'hsm',      label: 'PKCS#11 HSM',       sublabel: 'CKM_EDDSA · session pool', accent: 'rose',  x: 320,  y: 580, w: 120, h: 40 },
  { id: 'replay',   label: 'ReplayDB',          sublabel: 'MAC-protected · atomic',  accent: 'rose',  x: 600,  y: 620, w: 110, h: 40 },
  { id: 'audit',    label: 'Audit Log',         sublabel: 'BLAKE2b chain · Ed25519',  accent: 'rose',  x: 880,  y: 580, w: 120, h: 40 },

  { id: 'receiver', label: 'Receiver CLI',      sublabel: 'decrypt · audit-verify', accent: 'cyan',   x: 1070, y: 340, w: 100, h: 38 }
]

interface ConnSpec { from: string; to: string; reverse?: boolean; speed?: number }

const conns: ConnSpec[] = [
  // Sender feeds the crypto primitives + core
  { from: 'sender',   to: 'kem',     speed: 4.5 },
  { from: 'sender',   to: 'sig',     speed: 5.0 },
  { from: 'sender',   to: 'core',    speed: 3.8 },

  // Primitives feed the core
  { from: 'kem',      to: 'core',    speed: 4.2 },
  { from: 'sig',      to: 'core',    speed: 4.0 },
  { from: 'aead',     to: 'core',    speed: 3.6 },

  // Core fans out to persistence
  { from: 'core',     to: 'hsm',     speed: 5.2 },
  { from: 'core',     to: 'replay',  speed: 4.6 },
  { from: 'core',     to: 'audit',   speed: 5.8 },

  // Core delivers to receiver, which fans into receive-side primitives
  { from: 'core',     to: 'receiver', speed: 3.4 },
  { from: 'aead',     to: 'receiver', speed: 4.8 },
  { from: 'replay',   to: 'receiver', speed: 5.4 }
]

const nodeById = (id: string) => nodes.find(n => n.id === id)!

interface ComputedConn {
  id: string
  d: string
  speed: number
  delay: number
  accent: string
  fromId: string
  toId: string
}

/** Cubic bezier between two anchors with a smooth, perpendicular bias. */
function buildPath(ax: number, ay: number, bx: number, by: number): string {
  const dx = bx - ax
  const dy = by - ay
  const dist = Math.hypot(dx, dy)
  const bias = Math.min(0.42, 110 / dist)
  // Control points perpendicular-ish to the segment so the curve breathes.
  const c1x = ax + dx * 0.4
  const c1y = ay + dy * bias
  const c2x = bx - dx * 0.4
  const c2y = by - dy * bias
  return `M ${ax} ${ay} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${bx} ${by}`
}

function anchor(n: Node, towards: Node) {
  // Pick the anchor on the card border nearest the target so the line
  // doesn't crash through the centre of the box.
  const sign = (v: number) => (v < 0 ? -1 : v > 0 ? 1 : 0)
  const dx = towards.x - n.x
  const dy = towards.y - n.y
  if (Math.abs(dx) > Math.abs(dy)) {
    return { x: n.x + sign(dx) * (n.w + 6), y: n.y }
  }
  return { x: n.x, y: n.y + sign(dy) * (n.h + 6) }
}

const computedConns = computed<ComputedConn[]>(() => {
  return conns.map((c, i) => {
    const a = nodeById(c.from)
    const b = nodeById(c.to)
    const aA = anchor(a, b)
    const aB = anchor(b, a)
    return {
      id: `${c.from}-${c.to}`,
      d: buildPath(aA.x, aA.y, aB.x, aB.y),
      speed: c.speed ?? 4,
      delay: (i * 0.18) % 2.4,
      accent: a.accent,
      fromId: c.from,
      toId: c.to
    }
  })
})

/** Path "draw" entrance — feed a length hint to CSS via custom prop. */
function pathLength(_d: string): number {
  // Real length resolved client-side once the SVG mounts; the constant is
  // a safe upper bound so the dashoffset animation always fully reveals.
  return 1400
}

const rootRef = ref<HTMLElement | null>(null)
const visible = ref(false)
const focused = ref<string | null>(null)

onMounted(() => {
  if (!rootRef.value) return
  const io = new IntersectionObserver(entries => {
    for (const e of entries) if (e.isIntersecting) visible.value = true
  }, { threshold: 0.15 })
  io.observe(rootRef.value)
  onUnmounted(() => io.disconnect())
})

const accentColor: Record<Node['accent'], { fill: string; stroke: string; text: string }> = {
  cyan:   { fill: 'var(--nx-arch-cyan-fill)',   stroke: 'var(--nx-arch-cyan-stroke)',   text: 'var(--nx-arch-cyan-text)' },
  violet: { fill: 'var(--nx-arch-violet-fill)', stroke: 'var(--nx-arch-violet-stroke)', text: 'var(--nx-arch-violet-text)' },
  rose:   { fill: 'var(--nx-arch-rose-fill)',   stroke: 'var(--nx-arch-rose-stroke)',   text: 'var(--nx-arch-rose-text)' },
  amber:  { fill: 'var(--nx-arch-amber-fill)',  stroke: 'var(--nx-arch-amber-stroke)',  text: 'var(--nx-arch-amber-text)' }
}
</script>

<template>
  <figure ref="rootRef" class="nx-arch" :class="{ 'is-visible': visible }" aria-label="Nocturne-KX architecture diagram">
    <div class="nx-arch__legend">
      <span class="nx-arch__chip nx-arch__chip--cyan">CLI surface</span>
      <span class="nx-arch__chip nx-arch__chip--violet">PQC primitive</span>
      <span class="nx-arch__chip nx-arch__chip--amber">AEAD</span>
      <span class="nx-arch__chip nx-arch__chip--rose">Persistence</span>
    </div>

    <svg
      class="nx-arch__svg"
      :viewBox="`0 0 ${VB_W} ${VB_H}`"
      role="img"
      preserveAspectRatio="xMidYMid meet"
    >
      <defs>
        <!-- Subtle dot grid background -->
        <pattern id="nx-grid" width="32" height="32" patternUnits="userSpaceOnUse">
          <circle cx="1" cy="1" r="0.9" fill="var(--nx-arch-grid)" />
        </pattern>

        <linearGradient id="nx-core-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%"   stop-color="#22d3ee" />
          <stop offset="55%"  stop-color="#a855f7" />
          <stop offset="100%" stop-color="#f43f5e" />
        </linearGradient>

        <radialGradient id="nx-glow" cx="50%" cy="50%" r="50%">
          <stop offset="0%"  stop-color="rgba(168,85,247,0.20)" />
          <stop offset="60%" stop-color="rgba(168,85,247,0.05)" />
          <stop offset="100%" stop-color="rgba(168,85,247,0)" />
        </radialGradient>

        <!-- Soft drop shadow for cards -->
        <filter id="nx-shadow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur in="SourceAlpha" stdDeviation="6" />
          <feOffset dy="6" />
          <feComponentTransfer><feFuncA type="linear" slope="0.22" /></feComponentTransfer>
          <feMerge><feMergeNode /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      <!-- Background atmosphere -->
      <rect x="0" y="0" :width="VB_W" :height="VB_H" fill="url(#nx-grid)" opacity="0.55" />
      <circle :cx="VB_W / 2" :cy="VB_H / 2" r="320" fill="url(#nx-glow)" />

      <!-- Connector paths -->
      <g class="nx-arch__paths">
        <path
          v-for="(c, i) in computedConns"
          :key="`p-${c.id}`"
          :d="c.d"
          fill="none"
          stroke="var(--nx-arch-path)"
          stroke-width="1.4"
          stroke-dasharray="3 8"
          stroke-linecap="round"
          :class="['nx-arch__path', { 'is-focused': focused === c.fromId || focused === c.toId }]"
          :style="{
            '--path-len': pathLength(c.d),
            '--path-delay': `${0.35 + i * 0.08}s`
          }"
        />
      </g>

      <!-- Traveling dots -->
      <g class="nx-arch__beams">
        <g v-for="(c, i) in computedConns" :key="`b-${c.id}`">
          <circle
            r="3.4"
            :fill="`var(--nx-arch-${c.accent}-beam)`"
            :class="['nx-arch__beam', { 'is-focused': focused === c.fromId || focused === c.toId }]"
          >
            <animateMotion
              :dur="`${c.speed}s`"
              repeatCount="indefinite"
              :begin="`${c.delay}s`"
              :path="c.d"
              rotate="auto"
            />
            <animate
              attributeName="opacity"
              :dur="`${c.speed}s`"
              repeatCount="indefinite"
              values="0;1;1;1;0"
              keyTimes="0;0.1;0.5;0.9;1"
              :begin="`${c.delay}s`"
            />
          </circle>
          <!-- second offset bead -->
          <circle
            r="2.4"
            :fill="`var(--nx-arch-${c.accent}-beam)`"
            class="nx-arch__beam"
            opacity="0.65"
          >
            <animateMotion
              :dur="`${c.speed}s`"
              repeatCount="indefinite"
              :begin="`${c.delay + c.speed / 3}s`"
              :path="c.d"
              rotate="auto"
            />
          </circle>
        </g>
      </g>

      <!-- Node cards -->
      <g class="nx-arch__nodes">
        <g
          v-for="(n, i) in nodes"
          :key="n.id"
          :class="[
            'nx-arch__node',
            `nx-arch__node--${n.accent}`,
            { 'is-core': n.id === 'core', 'is-focused': focused === n.id }
          ]"
          :transform="`translate(${n.x - n.w}, ${n.y - n.h})`"
          :style="{ '--node-delay': `${0.15 + i * 0.05}s` }"
          @mouseenter="focused = n.id"
          @mouseleave="focused = null"
        >
          <rect
            :width="n.w * 2"
            :height="n.h * 2"
            rx="14"
            ry="14"
            :fill="n.id === 'core' ? 'url(#nx-core-grad)' : accentColor[n.accent].fill"
            :stroke="n.id === 'core' ? 'rgba(255,255,255,0.25)' : accentColor[n.accent].stroke"
            stroke-width="1.4"
            filter="url(#nx-shadow)"
          />
          <text
            :x="n.w"
            :y="n.h - (n.sublabel ? 3 : 5)"
            text-anchor="middle"
            class="nx-arch__node-label"
            :style="{ fill: n.id === 'core' ? '#0a0a0f' : accentColor[n.accent].text }"
          >{{ n.label }}</text>
          <text
            v-if="n.sublabel"
            :x="n.w"
            :y="n.h + 14"
            text-anchor="middle"
            class="nx-arch__node-sublabel"
            :style="{ fill: n.id === 'core' ? 'rgba(10,10,15,0.7)' : 'var(--nx-arch-sub)' }"
          >{{ n.sublabel }}</text>
        </g>
      </g>
    </svg>

    <figcaption class="nx-arch__caption">
      Hover any node to highlight its connections. Every animated bead
      represents a real call, encapsulate, sign, record, decapsulate, verify.
    </figcaption>
  </figure>
</template>

<style scoped>
.nx-arch {
  position: relative;
  margin: 32px 0 40px;
  padding: 22px 18px 16px;
  border-radius: 18px;
  background: var(--nx-arch-bg);
  border: 1px solid var(--nx-arch-border);
  overflow: hidden;
  opacity: 0;
  transform: translateY(14px);
  transition: opacity 700ms cubic-bezier(0.16, 1, 0.3, 1),
              transform 700ms cubic-bezier(0.16, 1, 0.3, 1);
}
.nx-arch.is-visible {
  opacity: 1;
  transform: translateY(0);
}

/* Theme variables — flip cleanly between modes via VitePress's .dark on
   the root element. The component itself never refers to a colour twice. */
:root:not(.dark) {
  --nx-arch-bg: linear-gradient(180deg, #ffffff 0%, #fafbff 100%);
  --nx-arch-border: rgba(15, 23, 42, 0.08);
  --nx-arch-grid: rgba(15, 23, 42, 0.07);
  --nx-arch-path: rgba(99, 102, 241, 0.5);
  --nx-arch-sub: rgba(71, 85, 105, 0.85);

  --nx-arch-cyan-fill:   rgba(34, 211, 238, 0.10);
  --nx-arch-cyan-stroke: rgba(8, 145, 178, 0.65);
  --nx-arch-cyan-text:   #0e7490;
  --nx-arch-cyan-beam:   #06b6d4;

  --nx-arch-violet-fill:   rgba(168, 85, 247, 0.10);
  --nx-arch-violet-stroke: rgba(126, 34, 206, 0.60);
  --nx-arch-violet-text:   #6b21a8;
  --nx-arch-violet-beam:   #a855f7;

  --nx-arch-rose-fill:   rgba(244, 63, 94, 0.10);
  --nx-arch-rose-stroke: rgba(190, 18, 60, 0.55);
  --nx-arch-rose-text:   #9f1239;
  --nx-arch-rose-beam:   #f43f5e;

  --nx-arch-amber-fill:   rgba(245, 158, 11, 0.10);
  --nx-arch-amber-stroke: rgba(180, 83, 9, 0.55);
  --nx-arch-amber-text:   #92400e;
  --nx-arch-amber-beam:   #f59e0b;
}

.dark {
  --nx-arch-bg: linear-gradient(180deg, #0d0e15 0%, #11121a 100%);
  --nx-arch-border: rgba(148, 163, 184, 0.10);
  --nx-arch-grid: rgba(148, 163, 184, 0.10);
  --nx-arch-path: rgba(103, 232, 249, 0.42);
  --nx-arch-sub: rgba(203, 213, 225, 0.65);

  --nx-arch-cyan-fill:   rgba(34, 211, 238, 0.10);
  --nx-arch-cyan-stroke: rgba(34, 211, 238, 0.55);
  --nx-arch-cyan-text:   #67e8f9;
  --nx-arch-cyan-beam:   #67e8f9;

  --nx-arch-violet-fill:   rgba(168, 85, 247, 0.10);
  --nx-arch-violet-stroke: rgba(168, 85, 247, 0.55);
  --nx-arch-violet-text:   #c084fc;
  --nx-arch-violet-beam:   #c084fc;

  --nx-arch-rose-fill:   rgba(244, 63, 94, 0.10);
  --nx-arch-rose-stroke: rgba(244, 63, 94, 0.55);
  --nx-arch-rose-text:   #fda4af;
  --nx-arch-rose-beam:   #fda4af;

  --nx-arch-amber-fill:   rgba(245, 158, 11, 0.10);
  --nx-arch-amber-stroke: rgba(245, 158, 11, 0.55);
  --nx-arch-amber-text:   #fcd34d;
  --nx-arch-amber-beam:   #fcd34d;
}

.nx-arch__legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
  padding-left: 6px;
}

.nx-arch__chip {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  padding: 4px 10px;
  border-radius: 999px;
  font-weight: 500;
  letter-spacing: 0.01em;
}
.nx-arch__chip--cyan   { color: var(--nx-arch-cyan-text);   background: var(--nx-arch-cyan-fill);   border: 1px solid var(--nx-arch-cyan-stroke); }
.nx-arch__chip--violet { color: var(--nx-arch-violet-text); background: var(--nx-arch-violet-fill); border: 1px solid var(--nx-arch-violet-stroke); }
.nx-arch__chip--rose   { color: var(--nx-arch-rose-text);   background: var(--nx-arch-rose-fill);   border: 1px solid var(--nx-arch-rose-stroke); }
.nx-arch__chip--amber  { color: var(--nx-arch-amber-text);  background: var(--nx-arch-amber-fill);  border: 1px solid var(--nx-arch-amber-stroke); }

.nx-arch__svg {
  display: block;
  width: 100%;
  height: auto;
  max-height: 560px;
}

/* Paths: draw on reveal */
.nx-arch__path {
  stroke-dasharray: 3 8;
  stroke-dashoffset: var(--path-len, 1400);
  animation: nx-arch-path-draw 1.6s cubic-bezier(0.22, 1, 0.36, 1) var(--path-delay, 0.4s) forwards;
  transition: stroke 250ms ease, opacity 250ms ease;
}
.nx-arch.is-visible .nx-arch__path {
  /* triggers the animation only after the IntersectionObserver fires */
  animation-play-state: running;
}
.nx-arch__path.is-focused {
  stroke: var(--nx-arch-cyan-beam) !important;
  opacity: 1;
}
.nx-arch__paths .nx-arch__path:not(.is-focused) {
  opacity: 0.85;
}
.nx-arch__paths:has(.is-focused) .nx-arch__path:not(.is-focused) {
  opacity: 0.18;
}

@keyframes nx-arch-path-draw {
  to { stroke-dashoffset: 0; }
}

/* Beams */
.nx-arch__beam {
  filter: drop-shadow(0 0 4px currentColor);
}

/* Nodes */
.nx-arch__node {
  opacity: 0;
  transform-origin: center;
  animation: nx-arch-node-pop 700ms cubic-bezier(0.34, 1.35, 0.64, 1) var(--node-delay, 0.2s) forwards;
  cursor: pointer;
  transition: transform 200ms ease, filter 200ms ease;
}
.nx-arch.is-visible .nx-arch__node {
  animation-play-state: running;
}

.nx-arch__node:hover {
  filter: brightness(1.06);
}
.nx-arch__node:hover rect {
  filter: drop-shadow(0 12px 28px rgba(34, 211, 238, 0.30));
}
.nx-arch__node.is-core rect {
  filter: drop-shadow(0 14px 32px rgba(168, 85, 247, 0.35));
}

.nx-arch__node-label {
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  font-weight: 600;
  letter-spacing: -0.005em;
}
.nx-arch__node-sublabel {
  font-family: 'JetBrains Mono', monospace;
  font-size: 11px;
  font-weight: 500;
}

@keyframes nx-arch-node-pop {
  0%   { opacity: 0; transform: translate3d(var(--tx, 0), 10px, 0) scale(0.86); }
  60%  { opacity: 1; transform: translate3d(var(--tx, 0), 0, 0) scale(1.04); }
  100% { opacity: 1; transform: translate3d(var(--tx, 0), 0, 0) scale(1); }
}

.nx-arch__caption {
  font-size: 0.82rem;
  color: var(--vp-c-text-3);
  text-align: center;
  margin-top: 8px;
  padding: 0 16px;
}

@media (prefers-reduced-motion: reduce) {
  .nx-arch {
    opacity: 1;
    transform: none;
    transition: none;
  }
  .nx-arch__path,
  .nx-arch__node {
    animation: none !important;
    opacity: 1 !important;
    stroke-dashoffset: 0 !important;
    transform: none !important;
  }
  .nx-arch__beam,
  .nx-arch__beam animateMotion,
  .nx-arch__beam animate {
    display: none;
  }
}
</style>
