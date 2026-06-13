import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import './style.css'

import HeroAnimated from './components/HeroAnimated.vue'
import FeatureGrid from './components/FeatureGrid.vue'
import WireFormat from './components/WireFormat.vue'
import CodeShowcase from './components/CodeShowcase.vue'
import NocturneArchFlow from './components/NocturneArchFlow.vue'
import NocturneTimeline from './components/NocturneTimeline.vue'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('HeroAnimated', HeroAnimated)
    app.component('FeatureGrid', FeatureGrid)
    app.component('WireFormat', WireFormat)
    app.component('CodeShowcase', CodeShowcase)
    app.component('NocturneArchFlow', NocturneArchFlow)
    app.component('NocturneTimeline', NocturneTimeline)
  }
} satisfies Theme
