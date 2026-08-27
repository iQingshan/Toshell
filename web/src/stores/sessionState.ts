interface SessionState {
  terminalHistory: Array<{id: string, type: string, content: string}>
  currentPath: string
  files: Array<{name: string, size: number, isDir: boolean, modTime: string}>
  processes: Array<{pid: number, name: string, cpu: string, memory: string}>
}

const sessionStates: Map<string, SessionState> = new Map()

export function getSessionState(sessionId: string): SessionState {
  if (!sessionStates.has(sessionId)) {
    sessionStates.set(sessionId, {
      terminalHistory: [
        { id: '1', type: 'system', content: 'ToShell Terminal - 输入命令后按回车执行' }
      ],
      currentPath: '',
      files: [],
      processes: []
    })
  }
  return sessionStates.get(sessionId)!
}

export function updateSessionState(sessionId: string, updates: Partial<SessionState>): void {
  const state = getSessionState(sessionId)
  sessionStates.set(sessionId, { ...state, ...updates })
}

export function addTerminalHistory(sessionId: string, message: {id: string, type: string, content: string}): void {
  const state = getSessionState(sessionId)
  state.terminalHistory = [...state.terminalHistory, message]
  sessionStates.set(sessionId, state)
}

export function clearSessionState(sessionId: string): void {
  sessionStates.delete(sessionId)
}

export function getDefaultPath(os: string): string {
  // Windows 根为 "\"（显示所有盘符）
  return os?.toLowerCase() === 'windows' ? '\\' : '/'
}
