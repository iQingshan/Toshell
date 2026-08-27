import { ReactNode, useState } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Users,
  Terminal,
  FileText,
  Settings,
  LogOut,
  Menu,
  X,
  Shell,
  Sun,
  Moon,
  FileCode,
  Network,
  Package,
  Radio,
  Layers,
  Info,
  Sparkles,
  Clock,
  Wifi,
} from 'lucide-react'
import { useAuthStore } from '../stores/auth'
import { useThemeStore } from '../stores/theme'
import { NotificationCenter } from './NotificationCenter'
import './Layout.css'

interface NavItem {
  path: string
  icon: ReactNode
  label: string
}

interface NavGroup {
  title: string
  items: NavItem[]
}

const navGroups: NavGroup[] = [
  {
    title: '核心',
    items: [
      { path: '/', icon: <LayoutDashboard size={20} />, label: '仪表' },
      { path: '/sessions', icon: <Users size={20} />, label: '会话' },
      { path: '/builds', icon: <FileCode size={20} />, label: '载荷' },
      { path: '/terminal', icon: <Terminal size={20} />, label: '终端' },
      { path: '/templates', icon: <Layers size={20} />, label: '任务' },
    ],
  },
  {
    title: '网络',
    items: [
      { path: '/tunnels', icon: <Network size={20} />, label: '隧道' },
      { path: '/listeners', icon: <Radio size={20} />, label: '监听' },
      { path: '/channels', icon: <Wifi size={20} />, label: '通道' },
      { path: '/plugins', icon: <Package size={20} />, label: '插件' },
    ],
  },
  {
    title: '洞察',
    items: [
      { path: '/logs', icon: <FileText size={20} />, label: '日志' },
      { path: '/timeline', icon: <Clock size={20} />, label: '时间线' },
      { path: '/copilot', icon: <Sparkles size={20} />, label: '副驾驶' },
    ],
  },
  {
    title: '系统',
    items: [
      { path: '/settings', icon: <Settings size={20} />, label: '设置' },
      { path: '/about', icon: <Info size={20} />, label: '关于' },
    ],
  },
]

export function Layout({ children }: { children: ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const location = useLocation()
  const { logout, username } = useAuthStore()
  const { theme, toggleTheme } = useThemeStore()

  const handleLogout = () => {
    logout()
    window.location.href = '/login'
  }

  return (
    <div className="layout">
      <aside className={`sidebar ${sidebarOpen ? 'open' : 'collapsed'}`}>
        <div className="sidebar-header">
          <div className="logo">
            <Shell size={28} className="logo-icon" />
            {sidebarOpen && <span className="logo-text">ToShell</span>}
          </div>
          <button className="toggle-btn" onClick={() => setSidebarOpen(!sidebarOpen)}>
            {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </div>

        <nav className="nav">
          {navGroups.map((group) => (
            <div key={group.title} className="nav-group">
              {sidebarOpen && <div className="nav-group-title">{group.title}</div>}
              {group.items.map((item) => (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                >
                  {item.icon}
                  {sidebarOpen && <span>{item.label}</span>}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">
          {sidebarOpen && (
            <div className="user-info">
              <div className="avatar">{username?.charAt(0).toUpperCase()}</div>
              <span className="username">{username}</span>
            </div>
          )}
          <button className="logout-btn" onClick={handleLogout}>
            <LogOut size={18} />
            {sidebarOpen && <span>退出</span>}
          </button>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="page-title">
            {navGroups.flatMap((g) => g.items).find((item) => item.path === location.pathname)?.label || 'ToShell'}
          </div>
          <div className="topbar-actions">
            <NotificationCenter />
            <button className="theme-toggle" onClick={toggleTheme} title={theme === 'dark' ? '切换到亮色模式' : '切换到暗色模式'}>
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
            <div className="status-indicator online">
              <span className="status-dot" />
              在线
            </div>
          </div>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  )
}
