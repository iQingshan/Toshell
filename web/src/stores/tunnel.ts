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
}

interface TunnelState {
  servers: SOCKS5Server[]
  loading: boolean
  error: string | null
  fetchTunnels: () => Promise<void>
  createTunnel: (sessionId: string, localPort: number) => Promise<{ success: boolean; error?: string; local_port?: number }>
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

      createTunnel: async (sessionId: string, localPort: number) => {
        try {
          const response = await tunnelApi.create(sessionId, localPort)
          if (response.data?.success) {
            const newServer: SOCKS5Server = {
              session_id: sessionId,
              local_port: response.data.local_port,
              tunnels: [],
            }
            set(state => ({
              servers: [...state.servers, newServer],
              error: null
            }))
            return { success: true, local_port: response.data.local_port }
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
