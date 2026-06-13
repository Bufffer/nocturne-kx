<script setup lang="ts">
/* --------------------------------------------------------------------------
   CodeShowcase, three-pane "in 30 seconds" demo: sender, receiver,
   attacker. Each pane is a static highlighted snippet; tabs swap which
   pane sits in the foreground on mobile.
   -------------------------------------------------------------------------- */
import { ref } from 'vue'

type Tab = 'sender' | 'receiver' | 'attacker'
const active = ref<Tab>('sender')
</script>

<template>
  <section class="nx-showcase">
    <header class="nx-showcase__header">
      <h2 class="nx-showcase__title">
        Encrypt to a post-quantum receiver in 30 seconds.
      </h2>
      <p class="nx-showcase__sub">
        Three calls, one binary. Hybrid X25519 + ML-KEM-1024, hash-chained audit log,
        replay DB on disk, defaults are production-grade.
      </p>
    </header>

    <div class="nx-showcase__tabs" role="tablist">
      <button
        v-for="t in (['sender','receiver','attacker'] as const)"
        :key="t"
        role="tab"
        :aria-selected="active === t"
        :class="['nx-showcase__tab', { 'is-active': active === t }]"
        @click="active = t"
      >{{ t === 'attacker' ? 'attacker → rejected' : t }}</button>
    </div>

    <div class="nx-showcase__panes">
      <article :class="['nx-pane', { 'is-active': active === 'sender' }]" data-role="sender">
        <header class="nx-pane__head">
          <span class="nx-pane__dot nx-pane__dot--ok" /> sender@alice
        </header>
<pre class="nx-pane__code"><code><span class="hl-comment"># 1. Generate hybrid PQC receiver keys (run once on bob's box)</span>
$ nocturne-kx gen-receiver ./keys --kem <span class="hl-str">hybrid</span>
Wrote Hybrid-X25519-ML-KEM-1024 receiver keys to ./keys
  (pk=1600B, sk=3200B)

<span class="hl-comment"># 2. Generate an ML-DSA-87 signer (post-quantum signatures)</span>
$ nocturne-kx gen-signer ./keys --sig-type <span class="hl-str">hybrid</span>
Wrote Hybrid-Ed25519-ML-DSA-87 signer keys to ./keys
  (pk=2624B, sk=4960B)

<span class="hl-comment"># 3. Encrypt, hybrid KEM + hybrid signature, single call</span>
$ echo <span class="hl-str">"meet at midnight"</span> | nocturne-kx encrypt \
    --rx-pk    ./keys/receiver_hybrid_pk.bin \
    --kem      <span class="hl-str">hybrid</span> \
    --pqc-sign-key ./keys/sender_hybrid_sig_sk.bin \
    --pqc-sig-type <span class="hl-str">hybrid</span> \
    --aad      <span class="hl-str">"session-7f3a"</span> \
    --in /dev/stdin --out msg.pkt
ok: 4859 bytes written
</code></pre>
      </article>

      <article :class="['nx-pane', { 'is-active': active === 'receiver' }]" data-role="receiver">
        <header class="nx-pane__head">
          <span class="nx-pane__dot nx-pane__dot--ok" /> receiver@bob
        </header>
<pre class="nx-pane__code"><code><span class="hl-comment"># 1. Auto-detect KEM mode from the packet header</span>
$ nocturne-kx decrypt \
    --rx-pk ./keys/receiver_hybrid_pk.bin \
    --rx-sk ./keys/receiver_hybrid_sk.bin \
    --expect-pqc-signer ./keys/sender_hybrid_sig_pk.bin \
    --pqc-sig-type <span class="hl-str">hybrid</span> \
    --replay-db ./replay.db \
    --in msg.pkt --out msg.txt

$ cat msg.txt
meet at midnight

<span class="hl-comment"># 2. Audit log records every step, hash-chained + Ed25519-signed</span>
$ nocturne-kx audit-verify ./audit.log \
    --expect-signer ./keys/auditor_pk.bin
ok: 247 records verified
chain head: 7f3a...c4d2
</code></pre>
      </article>

      <article :class="['nx-pane', { 'is-active': active === 'attacker' }]" data-role="attacker">
        <header class="nx-pane__head">
          <span class="nx-pane__dot nx-pane__dot--err" /> attacker@mallory
        </header>
<pre class="nx-pane__code"><code><span class="hl-comment"># Replay an already-delivered packet (P1 patent-pending defence)</span>
$ nocturne-kx decrypt \
    --rx-pk ./keys/receiver_hybrid_pk.bin \
    --rx-sk ./keys/receiver_hybrid_sk.bin \
    --replay-db ./replay.db \
    --in msg.pkt --out stolen.txt
<span class="hl-err">ReplayDetected: counter 42 ≤ last seen 42</span>
exit 2

<span class="hl-comment"># Substitute a different signer's PK</span>
$ nocturne-kx decrypt ... --expect-pqc-signer ./mallory_pk.bin ...
<span class="hl-err">SignatureVerifyFailed: pinned signer does not match packet</span>
exit 2

<span class="hl-comment"># Flip a single ciphertext bit</span>
$ printf '\\x01' | dd of=msg.pkt bs=1 seek=512 conv=notrunc 2&gt;/dev/null
$ nocturne-kx decrypt ...
<span class="hl-err">AeadAuthFailed: Poly1305 tag mismatch</span>
exit 2
</code></pre>
      </article>
    </div>
  </section>
</template>

<style scoped>
.nx-showcase {
  max-width: 1180px;
  margin: 0 auto;
  padding: 60px 24px 80px;
}

.nx-showcase__header {
  text-align: center;
  margin-bottom: 36px;
}

.nx-showcase__title {
  font-size: clamp(1.6rem, 2.8vw, 2.2rem);
  font-weight: 700;
  letter-spacing: -0.025em;
  line-height: 1.2;
  margin: 0 0 14px;
  color: var(--vp-c-text-1);
}

.nx-showcase__sub {
  font-size: 1.02rem;
  color: var(--vp-c-text-2);
  max-width: 620px;
  margin: 0 auto;
  line-height: 1.55;
}

.nx-showcase__tabs {
  display: flex;
  justify-content: center;
  gap: 8px;
  margin-bottom: 18px;
  flex-wrap: wrap;
}

.nx-showcase__tab {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  padding: 8px 16px;
  border-radius: 999px;
  background: transparent;
  border: 1px solid var(--vp-c-divider);
  color: var(--vp-c-text-2);
  cursor: pointer;
  transition: border-color 150ms ease, color 150ms ease, background 150ms ease;
}
.nx-showcase__tab.is-active {
  background: var(--vp-c-brand-soft);
  border-color: var(--nx-cyan);
  color: var(--nx-cyan);
}
.nx-showcase__tab:hover:not(.is-active) {
  border-color: var(--vp-c-text-3);
  color: var(--vp-c-text-1);
}

.nx-showcase__panes {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 14px;
}

@media (max-width: 920px) {
  .nx-showcase__panes {
    grid-template-columns: 1fr;
  }
  .nx-pane { display: none; }
  .nx-pane.is-active { display: block; }
}

.nx-pane {
  border: 1px solid var(--vp-c-divider);
  border-radius: 10px;
  background: var(--vp-code-block-bg, #0d0e15);
  overflow: hidden;
}

.nx-pane__head {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-bottom: 1px solid var(--vp-c-divider);
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.78rem;
  color: var(--vp-c-text-3);
  background: rgba(255, 255, 255, 0.02);
}
.nx-pane__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.nx-pane__dot--ok  { background: #22c55e; box-shadow: 0 0 8px #22c55e; }
.nx-pane__dot--err { background: #f43f5e; box-shadow: 0 0 8px #f43f5e; }

.nx-pane__code {
  margin: 0;
  padding: 16px 18px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.78rem;
  line-height: 1.6;
  color: #e2e8f0;
  overflow-x: auto;
  background: transparent;
}

.hl-comment { color: #64748b; font-style: italic; }
.hl-str     { color: #fbbf24; }
.hl-err     { color: #f43f5e; font-weight: 600; }
</style>
