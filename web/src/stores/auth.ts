import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  isAuthenticated: boolean
  token: string | null
  username: string | null
  login: (username: string, token: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      isAuthenticated: false,
      token: null,
      username: null,
      login: (username, token) => {
        localStorage.setItem('toshell-token', token)
        set({ isAuthenticated: true, token, username })
      },
      logout: () => {
        // 安全加固：登出必须清干净浏览器端敏感状态——
        // 残留的 toshell-token 会被 401 拦截器/WS 复用，等于登出失效
        localStorage.removeItem('toshell-token')
        localStorage.removeItem('toshell-ui-state')
        localStorage.removeItem('toshell-copilot')
        set({ isAuthenticated: false, token: null, username: null })
      },
    }),
    {
      name: 'toshell-auth',
    }
  )
)
