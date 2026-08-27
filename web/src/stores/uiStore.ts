import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { Session } from '../types'

// 跨页面保留的 UI 状态：切换路由后回来不丢失
// - sessionsPage: 会话页选中的会话 + 搜索词
// - 其它页面状态可按需扩展
interface UIState {
  selectedSession: Session | null
  sessionSearch: string
  setSelectedSession: (s: Session | null) => void
  setSessionSearch: (q: string) => void
  clearSessionSelection: () => void
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      selectedSession: null,
      sessionSearch: '',
      setSelectedSession: (s) => set({ selectedSession: s }),
      setSessionSearch: (q) => set({ sessionSearch: q }),
      clearSessionSelection: () => set({ selectedSession: null }),
    }),
    {
      name: 'toshell-ui-state',
      partialize: (state) => ({
        sessionSearch: state.sessionSearch,
        // selectedSession 只持久化关键字段（避免存过期的完整对象）
        selectedSession: state.selectedSession
          ? {
              id: state.selectedSession.id,
              hostname: state.selectedSession.hostname,
              username: state.selectedSession.username,
              os: state.selectedSession.os,
              arch: state.selectedSession.arch,
              pid: state.selectedSession.pid,
              process_name: state.selectedSession.process_name,
              process_path: state.selectedSession.process_path,
              ip_addresses: state.selectedSession.ip_addresses,
              mac_addresses: state.selectedSession.mac_addresses,
              domain: state.selectedSession.domain,
              first_seen: state.selectedSession.first_seen,
              last_seen: state.selectedSession.last_seen,
              status: state.selectedSession.status,
              listener: state.selectedSession.listener,
              remote_addr: state.selectedSession.remote_addr,
            }
          : null,
      }),
    }
  )
)
