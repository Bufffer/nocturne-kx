<script setup lang="ts">
/* --------------------------------------------------------------------------
   HeroAnimated, bespoke hero with a constellation of cipher glyphs
   drifting on a canvas, gradient overlay, gradient headline. Renders
   only client-side (canvas) so SSR builds skip it cleanly.
   -------------------------------------------------------------------------- */
import { onMounted, onUnmounted, ref } from 'vue'

const canvasRef = ref<HTMLCanvasElement | null>(null)
let rafId = 0
let particles: Particle[] = []

interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  glyph: string
  alpha: number
  size: number
}

const GLYPHS = [
  '0','1','f','c','7','a','3','9','b','d',
  'e','x','◇','◆','⬢','⬡','∎','∴','⨁','⊕'
]

function rand(min: number, max: number) {
  return Math.random() * (max - min) + min
}

function spawn(width: number, height: number): Particle {
  return {
    x: rand(0, width),
    y: rand(0, height),
    vx: rand(-0.12, 0.12),
    vy: rand(-0.08, 0.08),
    glyph: GLYPHS[Math.floor(Math.random() * GLYPHS.length)],
    alpha: rand(0.05, 0.32),
    size: rand(10, 18)
  }
}

function resize(canvas: HTMLCanvasElement) {
  const dpr = window.devicePixelRatio || 1
  const rect = canvas.getBoundingClientRect()
  canvas.width = rect.width * dpr
  canvas.height = rect.height * dpr
  const ctx = canvas.getContext('2d')!
  ctx.scale(dpr, dpr)
}

function start(canvas: HTMLCanvasElement) {
  const ctx = canvas.getContext('2d')!
  const rect = () => canvas.getBoundingClientRect()

  const reset = () => {
    resize(canvas)
    const r = rect()
    const density = Math.max(40, Math.floor((r.width * r.height) / 14000))
    particles = Array.from({ length: density }, () => spawn(r.width, r.height))
  }

  reset()
  window.addEventListener('resize', reset)

  const draw = () => {
    const r = rect()
    ctx.clearRect(0, 0, r.width, r.height)
    ctx.font = '14px "JetBrains Mono", monospace'

    // Glyph drift
    for (const p of particles) {
      p.x += p.vx
      p.y += p.vy
      if (p.x < -10) p.x = r.width + 10
      if (p.x > r.width + 10) p.x = -10
      if (p.y < -10) p.y = r.height + 10
      if (p.y > r.height + 10) p.y = -10

      ctx.font = `${p.size}px "JetBrains Mono", monospace`
      ctx.fillStyle = `rgba(186, 230, 253, ${p.alpha})`
      ctx.fillText(p.glyph, p.x, p.y)
    }

    // Subtle connecting filaments between near pairs
    ctx.lineWidth = 0.5
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const a = particles[i]
        const b = particles[j]
        const dx = a.x - b.x
        const dy = a.y - b.y
        const d2 = dx * dx + dy * dy
        if (d2 < 8000) {
          const alpha = (1 - d2 / 8000) * 0.08
          ctx.strokeStyle = `rgba(34, 211, 238, ${alpha})`
          ctx.beginPath()
          ctx.moveTo(a.x, a.y)
          ctx.lineTo(b.x, b.y)
          ctx.stroke()
        }
      }
    }

    rafId = requestAnimationFrame(draw)
  }

  draw()

  return () => {
    cancelAnimationFrame(rafId)
    window.removeEventListener('resize', reset)
  }
}

let cleanup: (() => void) | null = null

onMounted(() => {
  if (canvasRef.value) cleanup = start(canvasRef.value)
})

onUnmounted(() => {
  cleanup?.()
})
</script>

<template>
  <section class="nx-hero">
    <canvas ref="canvasRef" class="nx-hero__canvas" aria-hidden="true" />

    <div class="nx-hero__overlay" />

    <div class="nx-hero__content">
      <div class="nx-hero__badges">
        <span class="nx-badge">Patent pending</span>
        <span class="nx-badge nx-badge--violet">ML-KEM-1024</span>
        <span class="nx-badge nx-badge--violet">ML-DSA-87</span>
        <span class="nx-badge">C++23</span>
      </div>

      <h1 class="nx-hero__headline">
        Post-quantum encryption,<br />
        before quantum was a problem.
      </h1>

      <p class="nx-hero__tagline">
        Nocturne-KX is a C++23 cryptographic communication toolkit built on libsodium and ML-KEM-1024.
        Patent-pending hybrid PQC key exchange, bidirectional replay protection,
        and PKCS#11 HSM integration in a single binary.
      </p>

      <div class="nx-hero__actions">
        <a class="nx-cta nx-cta--primary" href="./guide/quickstart">
          Quickstart
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
        </a>
        <a class="nx-cta nx-cta--secondary" href="https://github.com/Bufffer/nocturne-kx" target="_blank" rel="noopener">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.11.79-.25.79-.56 0-.27-.01-1.18-.02-2.13-3.2.7-3.88-1.36-3.88-1.36-.52-1.33-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.69 1.25 3.35.96.1-.75.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.29 1.18-3.1-.12-.29-.51-1.46.11-3.04 0 0 .96-.31 3.15 1.18.91-.25 1.89-.38 2.86-.39.97.01 1.95.14 2.86.39 2.19-1.49 3.15-1.18 3.15-1.18.63 1.58.23 2.75.11 3.04.73.81 1.17 1.84 1.17 3.1 0 4.42-2.7 5.4-5.27 5.69.41.36.78 1.05.78 2.12 0 1.53-.01 2.77-.01 3.15 0 .31.21.68.8.56C20.21 21.39 23.5 17.08 23.5 12 23.5 5.65 18.35.5 12 .5Z"/></svg>
          GitHub
        </a>
      </div>

      <div class="nx-hero__metrics">
        <div class="nx-metric">
          <div class="nx-metric__value">256-bit</div>
          <div class="nx-metric__label">post-quantum security</div>
        </div>
        <div class="nx-metric">
          <div class="nx-metric__value">1.6 KiB</div>
          <div class="nx-metric__label">hybrid KEM ciphertext</div>
        </div>
        <div class="nx-metric">
          <div class="nx-metric__value">FIPS 140-3</div>
          <div class="nx-metric__label">PKCS#11 HSM ready</div>
        </div>
        <div class="nx-metric">
          <div class="nx-metric__value">Single binary</div>
          <div class="nx-metric__label">no runtime deps</div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.nx-hero {
  position: relative;
  margin: 0 auto;
  padding: clamp(64px, 12vh, 140px) 24px 80px;
  max-width: 1280px;
  overflow: hidden;
}

.nx-hero__canvas {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  z-index: 0;
  pointer-events: none;
}

.nx-hero__overlay {
  position: absolute;
  inset: 0;
  z-index: 1;
  background: radial-gradient(
    ellipse 70% 50% at 50% 30%,
    rgba(168, 85, 247, 0.08) 0%,
    transparent 70%
  );
  pointer-events: none;
}

.nx-hero__content {
  position: relative;
  z-index: 2;
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: 28px;
}

.nx-hero__badges {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 8px;
}

.nx-hero__headline {
  font-family: 'Inter', sans-serif;
  font-size: clamp(2.4rem, 6.5vw, 4.5rem);
  font-weight: 700;
  letter-spacing: -0.035em;
  line-height: 1.05;
  margin: 0;
  background: var(--nx-gradient-text);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.nx-hero__tagline {
  font-size: clamp(1rem, 1.6vw, 1.2rem);
  line-height: 1.65;
  color: var(--vp-c-text-2);
  max-width: 680px;
  margin: 0;
}

.nx-hero__actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  justify-content: center;
  margin-top: 8px;
}

.nx-cta {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 12px 22px;
  font-size: 0.95rem;
  font-weight: 600;
  border-radius: 999px;
  text-decoration: none;
  transition: transform 150ms ease, box-shadow 150ms ease, background 150ms ease;
}

.nx-cta--primary {
  background: var(--nx-gradient);
  color: #0a0a0f !important;
}
.nx-cta--primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 16px 32px -10px rgba(34, 211, 238, 0.5);
}

.nx-cta--secondary {
  background: rgba(255, 255, 255, 0.04);
  color: var(--vp-c-text-1) !important;
  border: 1px solid var(--vp-c-divider);
}
.nx-cta--secondary:hover {
  background: rgba(255, 255, 255, 0.08);
  border-color: var(--nx-cyan);
}

.nx-hero__metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 24px;
  margin-top: 40px;
  width: 100%;
  max-width: 880px;
  padding-top: 32px;
  border-top: 1px solid var(--vp-c-divider);
}

.nx-metric {
  text-align: center;
}
.nx-metric__value {
  font-family: 'JetBrains Mono', monospace;
  font-size: clamp(1.1rem, 1.8vw, 1.45rem);
  font-weight: 600;
  color: var(--vp-c-text-1);
  letter-spacing: -0.01em;
}
.nx-metric__label {
  font-size: 0.82rem;
  color: var(--vp-c-text-3);
  margin-top: 4px;
}
</style>
