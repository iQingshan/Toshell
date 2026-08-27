import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface CopilotTrace {
  name: string
  args?: Record<string, string>
  result?: string
  error?: string
}

export interface CopilotMsg {
  role: 'user' | 'assistant'
  content: string
  traces?: CopilotTrace[]
  error?: boolean
}

// AI 副驾驶聊天记录持久化：切换页面/刷新后不丢失
interface CopilotState {
  messages: CopilotMsg[]
  addMessage: (m: CopilotMsg) => void
  replaceLast: (m: CopilotMsg) => void
  clearMessages: () => void
}

export const useCopilotStore = create<CopilotState>()(
  persist(
    (set) => ({
      messages: [],
      addMessage: (m) => set((s) => ({ messages: [...s.messages, m] })),
      replaceLast: (m) =>
        set((s) => {
          const arr = [...s.messages]
          if (arr.length > 0) arr[arr.length - 1] = m
          return { messages: arr }
        }),
      clearMessages: () => set({ messages: [] }),
    }),
    { name: 'toshell-copilot' }
  )
)
