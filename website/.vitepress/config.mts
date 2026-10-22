import { defineConfig } from 'vitepress'

export default defineConfig({
  lang: 'zh-CN',
  title: 'CredScan',
  description: '公开渠道云凭据泄露的分钟级检测与响应——纯 Python 标准库实现',
  base: '/credscan/',
  head: [['link', { rel: 'icon', href: '/figures/overview.png' }]],
  themeConfig: {
    nav: [
      { text: '快速上手', link: '/guide/quickstart' },
      { text: '架构', link: '/guide/architecture' },
      { text: '检测器', link: '/guide/detectors' },
      { text: '运维面板', link: '/guide/panel' },
      { text: '实测', link: '/guide/evidence' },
      { text: '伦理红线', link: '/guide/ethics' },
      { text: 'GitHub', link: 'https://github.com/luohaoran616/credscan' }
    ],
    sidebar: [
      {
        text: '指南',
        items: [
          { text: '快速上手', link: '/guide/quickstart' },
          { text: '架构', link: '/guide/architecture' },
          { text: '检测器', link: '/guide/detectors' },
          { text: '运维面板', link: '/guide/panel' },
          { text: '实测与证据', link: '/guide/evidence' },
          { text: '伦理红线', link: '/guide/ethics' }
        ]
      }
    ],
    socialLinks: [
      { icon: 'github', link: 'https://github.com/luohaoran616/credscan' }
    ],
    outline: { level: [2, 3] }
  }
})
