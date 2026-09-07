import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// ─── 轻量 i18n：中/英文案字典 ─────────────────────────────────────
// 用法：useI18n() → { t, lang, setLang }；文案在字典里按语义 key 存。
// 页面文案陆续迁移到 key；未命中 key 时回退显示 key 本身，保证不白屏。

export type Lang = 'zh' | 'en'

export interface Dict {
  [key: string]: string
}

// 全量字典：key 语义化，值为中文；英文分支单独维护。
export const zhDict: Dict = {
  // 通用
  'common.online': '在线',
  'common.logout': '退出',
  'common.settings': '设置',
  'common.cancel': '取消',
  'common.confirm': '确认',
  'common.save': '保存',
  'common.delete': '删除',
  'common.edit': '编辑',
  'common.search': '搜索',
  'common.copy': '复制',
  'common.status': '状态',
  'common.action': '操作',
  'common.name': '名称',
  'common.id': 'ID',
  'common.type': '类型',
  'common.time': '时间',
  'common.host': '主机',
  'common.user': '用户',
  'common.os': '系统',
  'common.arch': '架构',
  // 导航分组
  'nav.core': '核心',
  'nav.network': '网络',
  'nav.intel': '洞察',
  'nav.system': '系统',
  // 导航项
  'nav.dashboard': '仪表',
  'nav.sessions': '会话',
  'nav.builds': '载荷',
  'nav.terminal': '终端',
  'nav.templates': '任务',
  'nav.tunnels': '隧道',
  'nav.listeners': '监听',
  'nav.channels': '通道',
  'nav.plugins': '插件',
  'nav.logs': '日志',
  'nav.timeline': '时间线',
  'nav.copilot': '副驾驶',
  'nav.settings': '设置',
  'nav.about': '关于',
  // 主题
  'theme.toLight': '切换到亮色模式',
  'theme.toDark': '切换到暗色模式',
  // 登录
  'login.subtitle': 'C2 命令控制平台',
  'login.username': '用户名',
  'login.password': '密码',
  'login.submit': '登录',
  'login.submitting': '登录中...',
  'login.footer': '请输入服务器账户凭据',
  'login.errBadCreds': '用户名或密码错误',
  'login.errConn': '登录失败，请检查服务器连接',
}

export const enDict: Dict = {
  'common.online': 'Online',
  'common.logout': 'Sign out',
  'common.settings': 'Settings',
  'common.cancel': 'Cancel',
  'common.confirm': 'Confirm',
  'common.save': 'Save',
  'common.delete': 'Delete',
  'common.edit': 'Edit',
  'common.search': 'Search',
  'common.copy': 'Copy',
  'common.status': 'Status',
  'common.action': 'Action',
  'common.name': 'Name',
  'common.id': 'ID',
  'common.type': 'Type',
  'common.time': 'Time',
  'common.host': 'Host',
  'common.user': 'User',
  'common.os': 'OS',
  'common.arch': 'Arch',
  'nav.core': 'Core',
  'nav.network': 'Network',
  'nav.intel': 'Insights',
  'nav.system': 'System',
  'nav.dashboard': 'Dashboard',
  'nav.sessions': 'Sessions',
  'nav.builds': 'Payloads',
  'nav.terminal': 'Terminal',
  'nav.templates': 'Tasks',
  'nav.tunnels': 'Tunnels',
  'nav.listeners': 'Listeners',
  'nav.channels': 'Channels',
  'nav.plugins': 'Plugins',
  'nav.logs': 'Logs',
  'nav.timeline': 'Timeline',
  'nav.copilot': 'Copilot',
  'nav.settings': 'Settings',
  'nav.about': 'About',
  'theme.toLight': 'Switch to light mode',
  'theme.toDark': 'Switch to dark mode',
  'login.subtitle': 'C2 Command & Control',
  'login.username': 'Username',
  'login.password': 'Password',
  'login.submit': 'Sign in',
  'login.submitting': 'Signing in...',
  'login.footer': 'Enter your server credentials',
  'login.errBadCreds': 'Invalid username or password',
  'login.errConn': 'Login failed. Please check the server connection.',
}

interface I18nState {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: string) => string
}

const dict = (lang: Lang): Dict => (lang === 'en' ? enDict : zhDict)

export const useI18n = create<I18nState>()(
  persist(
    (set, get) => ({
      lang: 'zh',
      setLang: (l: Lang) => set({ lang: l }),
      t: (key: string) => {
        const d = dict(get().lang)
        const v = d[key]
        return v !== undefined && v !== '' ? v : zhDict[key] ?? key
      },
    }),
    { name: 'toshell-lang' }
  )
)
