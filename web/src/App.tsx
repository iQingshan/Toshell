import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Sessions } from './pages/Sessions'
import { Builds } from './pages/Builds'
import { Terminal } from './pages/Terminal'
import { Shell } from './pages/Shell'
import { Logs } from './pages/Logs'
import { Settings } from './pages/Settings'
import { Tunnels } from './pages/Tunnels'
import Plugins from './pages/Plugins'
import { Listeners } from './pages/Listeners'
import { Templates } from './pages/Templates'
import { About } from './pages/About'
import { Copilot } from './pages/Copilot'
import { Timeline } from './pages/Timeline'
import { Channels } from './pages/Channels'
import { Login } from './pages/Login'
import { useAuthStore } from './stores/auth'
import { useThemeStore } from './stores/theme'
import { useEffect } from 'react'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function ThemeInitializer() {
  const initTheme = useThemeStore((state) => state.initTheme)
  useEffect(() => {
    initTheme()
  }, [initTheme])
  return null
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeInitializer />
      <Routes>
        <Route path="/login" element={<Login />} />
        {/* 全屏 Shell 页面 — 独立路由，不使用 Layout */}
        <Route path="/shell/:sessionId" element={<ProtectedRoute><Shell /></ProtectedRoute>} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout>
                <Routes>
                  {/* 默认路由 → Dashboard */}
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/dashboard" element={<Navigate to="/" replace />} />
                  <Route path="/sessions" element={<Sessions />} />
                  <Route path="/sessions/:id" element={<Sessions />} />
                  <Route path="/builds" element={<Builds />} />
                  <Route path="/terminal" element={<Terminal />} />
                  <Route path="/tunnels" element={<Tunnels />} />
                  <Route path="/plugins" element={<Plugins />} />
                  <Route path="/listeners" element={<Listeners />} />
                  <Route path="/templates" element={<Templates />} />
                  <Route path="/logs" element={<Logs />} />
                  <Route path="/timeline" element={<Timeline />} />
                  <Route path="/channels" element={<Channels />} />
                  <Route path="/copilot" element={<Copilot />} />
                  <Route path="/about" element={<About />} />
                  <Route path="/settings" element={<Settings />} />
                </Routes>
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  )
}
