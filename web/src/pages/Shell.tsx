import { useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import { TerminalComponent, type TerminalHandle } from '../components/Terminal'
import { ShellFileBrowser } from '../components/ShellFileBrowser'
import { sessionApi } from '../api'
import type { Session } from '../types'

export function Shell() {
  const { sessionId } = useParams<{ sessionId: string }>()
  const [session, setSession] = useState<Session | null>(null)
  const [currentPath, setCurrentPath] = useState<string>('')
  const terminalRef = useRef<TerminalHandle>(null)

  // 拉取会话信息，用主机名/用户名拼出友好的标题
  useEffect(() => {
    if (!sessionId) return
    setSession(null)
    sessionApi
      .get(sessionId)
      .then((r) => {
        setSession(r.data)
        // 初始化文件面板目录：按平台给默认根目录
        const isWin = r.data?.os?.toLowerCase().includes('windows')
        setCurrentPath((prev) => (prev ? prev : isWin ? '\\' : '/'))
      })
      .catch(() => setSession(null))
  }, [sessionId])

  const isWindows = !!(session?.os && session.os.toLowerCase().includes('windows'))

  const title = session
    ? `Shell - ${session.username ? session.username + '@' : ''}${session.hostname}${session.os ? ` (${session.os})` : ''}`
    : `Shell - ${sessionId ?? ''}`

  // 同步浏览器标签页标题
  useEffect(() => {
    document.title = title
  }, [title])

  // 文件面板独立浏览（双击目录 / 面包屑 / Home），不跟随终端 cd
  const handleNavigate = (path: string) => {
    setCurrentPath(path)
  }

  if (!sessionId) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', color: 'var(--color-text-muted)' }}>
        <p>无效的会话 ID</p>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', width: '100vw', height: '100vh', padding: 0, margin: 0, overflow: 'hidden' }}>
      {/* 左侧文件目录面板 */}
      {currentPath && (
        <ShellFileBrowser
          sessionId={sessionId}
          isWindows={isWindows}
          currentPath={currentPath}
          onNavigate={handleNavigate}
        />
      )}
      {/* 右侧交互式终端 */}
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        <TerminalComponent
          ref={terminalRef}
          wsPath={`/api/v1/sessions/${sessionId}/shell`}
          title={title}
          titleHighlight={session?.hostname}
          autoConnect
          followTheme
        />
      </div>
    </div>
  )
}
