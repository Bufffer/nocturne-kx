import { defineConfig } from 'vitepress'

// Repo deploys at https://bufffer.github.io/nocturne-kx/ — base must
// match the repo name so assets resolve correctly. Override via
// DOCS_BASE env var when previewing from a different root.
const base = process.env.DOCS_BASE ?? '/nocturne-kx/'

export default defineConfig({
  base,
  lang: 'en-US',
  title: 'Nocturne-KX',
  description:
    'Patent-pending hybrid post-quantum key encapsulation and bidirectional replay protection for nation-state threat models. C++23, libsodium, ML-KEM-1024.',

  cleanUrls: true,
  lastUpdated: true,
  appearance: 'dark',

  head: [
    ['meta', { name: 'theme-color', content: '#0a0a0f' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Nocturne-KX — post-quantum cryptographic toolkit' }],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'Patent-pending hybrid PQC KEM, bidirectional replay protection, PKCS#11 HSM. C++23, single binary.'
      }
    ],
    ['link', { rel: 'preconnect', href: 'https://rsms.me/' }],
    ['link', { rel: 'stylesheet', href: 'https://rsms.me/inter/inter.css' }]
  ],

  themeConfig: {
    siteTitle: 'Nocturne-KX',
    logo: { src: '/logo.svg', width: 24, height: 24 },

    nav: [
      { text: 'Guide', link: '/guide/quickstart', activeMatch: '/guide/' },
      { text: 'Architecture', link: '/architecture' },
      { text: 'CLI', link: '/cli/' },
      { text: 'PQC', link: '/pqc/' },
      {
        text: 'v4.0',
        items: [
          { text: 'Changelog', link: 'https://github.com/Bufffer/nocturne-kx/blob/main/CHANGELOG.md' },
          { text: 'Roadmap', link: '/roadmap' }
        ]
      }
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting started',
          items: [
            { text: 'Quickstart', link: '/guide/quickstart' },
            { text: 'Threat model', link: '/guide/threat-model' },
            { text: 'Architecture', link: '/architecture' }
          ]
        },
        {
          text: 'Operations',
          items: [
            { text: 'HSM integration', link: '/guide/hsm' },
            { text: 'Audit log', link: '/guide/audit' },
            { text: 'Replay protection', link: '/guide/replay' },
            { text: 'TLS transport', link: '/guide/tls' }
          ]
        }
      ],
      '/pqc/': [
        {
          text: 'Post-quantum',
          items: [
            { text: 'Overview', link: '/pqc/' },
            { text: 'KEM modes', link: '/pqc/kem' },
            { text: 'Signatures', link: '/pqc/signatures' },
            { text: 'Domain separation', link: '/pqc/domain-separation' }
          ]
        }
      ],
      '/cli/': [
        {
          text: 'CLI reference',
          items: [
            { text: 'Overview', link: '/cli/' },
            { text: 'gen-receiver', link: '/cli/gen-receiver' },
            { text: 'gen-signer', link: '/cli/gen-signer' },
            { text: 'encrypt', link: '/cli/encrypt' },
            { text: 'decrypt', link: '/cli/decrypt' },
            { text: 'tls-send / tls-recv', link: '/cli/tls' },
            { text: 'audit-verify', link: '/cli/audit-verify' }
          ]
        }
      ]
    },

    socialLinks: [{ icon: 'github', link: 'https://github.com/Bufffer/nocturne-kx' }],

    search: {
      provider: 'local',
      options: {
        detailedView: true
      }
    },

    editLink: {
      pattern: 'https://github.com/Bufffer/nocturne-kx/edit/main/docs/:path',
      text: 'Suggest changes to this page'
    },

    footer: {
      message:
        'Patent-pending hybrid PQC KEM and bidirectional replay protection. Nocturne-KX™ is a trademark of Halil İbrahim Serdaroğlu.',
      copyright: 'Copyright © 2025-2026 Halil İbrahim Serdaroğlu — MIT License'
    },

    outline: {
      level: [2, 3],
      label: 'On this page'
    }
  },

  markdown: {
    theme: { light: 'github-light', dark: 'github-dark-dimmed' },
    lineNumbers: false
  }
})
