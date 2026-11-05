import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { tunnelApi } from '../api'

export interface Tunnel {
  id: number
  target_addr: string
  target_port: number
  active: boolean
  created_at: string
  bytes_in: number
  bytes_out: number
}

export interface SOCKS5Server {
  session_id: string
  local_port: number
  tunnels: Tunnel[]
  /** 是否启用代理认证（列表接口回显；口令永不回传） */
  auth_enabled?: boolean
  // ── v1.4.1 追加：代理是库里的持久资源，服务端重启后自动恢复 ──
  id?: string
  /** 有效状态：running / error / stopped（运行态优先，其次用库里的状态） */
  status?: string
  /** 当前是否真的有监听（与库对账后的运行态真值） */
  listening?: boolean
  /** 本次启动是否由「重启恢复」重建（重启后无需手工重连） */
  restored?: boolean
  /** 是否已落库（无库降级时为 false：重启会丢） */
  persisted?: boolean
  /** 上次恢复/创建失败的原因（端口占用等）；不回显任何凭据 */
  last_error?: string
  remark?: string
  created_at?: string
  updated_at?: string
  protocol?: string
  mode?: string
  // ── v1.4.3 #16 追加：隧道归属会话（会话多了直接看主机名，不用逐个点开对 id）──
  session_host?: string
  session_user?: string
  session_status?: string
  session_alive?: boolean
}

interface TunnelState {
  servers: SOCKS5Server[]
  loading: boolean
  error: string | null
  fetchTunnels: () => Promise<void>
  createTunnel: (
    sessionId: string,
    localPort: number,
    authUser?: string,
    authPass?: string,
    remark?: string,
  ) => Promise<{ success: boolean; error?: string; local_port?: number; auth_enabled?: boolean }>
  closeTunnel: (sessionId: string) => Promise<{ success: boolean; error?: string }>
  clearError: () => void
}

export const useTunnelStore = create<TunnelState>()(
  persist(
    (set) => ({
      servers: [],
      loading: false,
      error: null,

      fetchTunnels: async () => {
        set({ loading: true, error: null })
        try {
          const response = await tunnelApi.list()
          const servers = response.data?.servers || []
          set({ servers, loading: false })
        } catch (error: any) {
          console.error('Failed to fetch tunnels:', error)
          set({ error: error.message, loading: false })
        }
      },

      createTunnel: async (sessionId: string, localPort: number, authUser?: string, authPass?: string, remark?: string) => {
        try {
          const response = await tunnelApi.create(sessionId, localPort, authUser, authPass, remark)
          if (response.data?.success) {
            const newServer: SOCKS5Server = {
              session_id: sessionId,
              local_port: response.data.local_port,
              tunnels: [],
              auth_enabled: !!response.data.auth_enabled,
              // v1.4.1：新建的代理已落库（persisted）、还没经过重启恢复（restored=false）
              id: response.data.id || sessionId,
              status: response.data.status || 'running',
              listening: true,
              restored: false,
              persisted: !!response.data.persisted,
              remark: response.data.remark || '',
            }
            set(state => ({
              servers: [...state.servers, newServer],
              error: null
            }))
            return {
              success: true,
              local_port: response.data.local_port,
              auth_enabled: !!response.data.auth_enabled,
            }
          } else {
            const errorMsg = response.data?.error || '未知错误'
            set({ error: errorMsg })
            return { success: false, error: errorMsg }
          }
        } catch (error: any) {
          const errorMsg = error.response?.data?.error || error.message
          set({ error: errorMsg })
          return { success: false, error: errorMsg }
        }
      },

      closeTunnel: async (sessionId: string) => {
        try {
          await tunnelApi.delete(sessionId)
          set(state => ({
            servers: state.servers.filter(s => s.session_id !== sessionId),
            error: null
          }))
          return { success: true }
        } catch (error: any) {
          const errorMsg = error.response?.data?.error || error.message
          set({ error: errorMsg })
          return { success: false, error: errorMsg }
        }
      },

      clearError: () => set({ error: null })
    }),
    {
      name: 'toshell-tunnels',
      partialize: (state) => ({ servers: state.servers })
    }
  )
)
