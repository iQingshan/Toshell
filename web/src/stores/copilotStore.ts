import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export interface CopilotTrace {
  name: string
  args?: Record<string, string>
  result?: string
  error?: string
}

/** Agent 执行过程中的一行日志（在会话气泡内联展示） */
export interface AgentAct {
  /** 行首小 icon（🔧/✅/❌/🎯/⚠️…），tool_result 文本自带状态图标时可留空 */
  i: string
  t: string
}

export interface CopilotMsg {
  role: 'user' | 'assistant'
  content: string
  traces?: CopilotTrace[]
  /** agent 执行日志行：目标/工具调用/结果/错误，按序渲染在正文上方 */
  acts?: AgentAct[]
  error?: boolean
  /** 是否仍在流式输出中（显示光标/进行中状态） */
  streaming?: boolean
  /** 是否在思考阶段（reasoning，还没开始输出正文） */
  thinking?: boolean
}

// AI 副驾驶聊天记录持久化：切换页面/刷新后不丢失
interface CopilotState {
  messages: CopilotMsg[]
  addMessage: (m: CopilotMsg) => void
  replaceLast: (m: CopilotMsg) => void
  /** 在最后一条 assistant 消息上追加流式增量（不存在则新建一条） */
  appendToLast: (m: Partial<CopilotMsg>) => void
  /** 覆盖最后一条 assistant 消息的 agent 执行日志行 */
  setLastActs: (acts: AgentAct[]) => void
  /** 结束最后一条流式消息（去掉 streaming 标记） */
  finalizeLast: () => void
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
      appendToLast: (m) =>
        set((s) => {
          const arr = [...s.messages]
          if (arr.length === 0) {
            arr.push({ role: 'assistant', content: '', ...m })
          } else {
            const last = { ...arr[arr.length - 1], ...m }
            arr[arr.length - 1] = last
          }
          return { messages: arr }
        }),
      setLastActs: (acts) =>
        set((s) => {
          const arr = [...s.messages]
          if (arr.length > 0) {
            arr[arr.length - 1] = { ...arr[arr.length - 1], acts }
          }
          return { messages: arr }
        }),
      finalizeLast: () =>
        set((s) => {
          const arr = [...s.messages]
          if (arr.length > 0) {
            arr[arr.length - 1] = { ...arr[arr.length - 1], streaming: false, thinking: false }
          }
          return { messages: arr }
        }),
      clearMessages: () => set({ messages: [] }),
    }),
    { name: 'toshell-copilot' }
  )
)
