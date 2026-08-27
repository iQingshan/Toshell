import { useState, useEffect, useRef, useCallback, forwardRef, useImperativeHandle } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { Wifi, WifiOff, Trash2, Loader2, Maximize2, Minimize2, ExternalLink } from 'lucide-react'
import '@xterm/xterm/css/xterm.css'
import './Terminal.css'

export interface TerminalProps {
  /** WebSocket shell path, e.g. /api/v1/sessions/{id}/shell */
  wsPath: string
  /** Display title */
  title?: string
  /** Substring of the title to highlight (e.g. hostname) */
  titleHighlight?: string
  /** Whether to auto-connect */
  autoConnect?: boolean
  /** Called when connection state changes */
  onConnectionChange?: (connected: boolean) => void
  /** Session ID for the shell connection */
  sessionId?: string
  /** Show open-in-new-tab button */
  showNewTab?: boolean
  /** Called when server pushes a CWD marker message (\x00CWD\x00<dir>) */
  onCWDChange?: (cwd: string) => void
  /** Follow global data-theme (dark/light) for xterm colors. Default false keeps classic dark look */
  followTheme?: boolean
}

export interface TerminalHandle {
  /** Inject raw text into the shell input stream (e.g. a cd command) */
  sendText: (text: string) => void
}

// xterm color themes
const XTERM_THEMES: Record<'dark' | 'light', Record<string, string>> = {
  dark: {
    background: '#1a1a2e',
    foreground: '#e0e0e0',
    cursor: '#e94560',
    cursorAccent: '#1a1a2e',
    selectionBackground: '#3a3a5c',
    black: '#1a1a2e',
    red: '#e94560',
    green: '#0f9d58',
    yellow: '#f4b400',
    blue: '#4285f4',
    magenta: '#aa46bb',
    cyan: '#24c1e0',
    white: '#e0e0e0',
    brightBlack: '#4a4a6a',
    brightRed: '#ff6b81',
    brightGreen: '#34c759',
    brightYellow: '#ffd60a',
    brightBlue: '#64b5f6',
    brightMagenta: '#ce93d8',
    brightCyan: '#4dd0e1',
    brightWhite: '#ffffff',
  },
  light: {
    background: '#ffffff',
    foreground: '#1a1a1a',
    cursor: '#6366f1',
    cursorAccent: '#ffffff',
    selectionBackground: '#e0e7ff',
    black: '#000000',
    red: '#dc2626',
    green: '#16a34a',
    yellow: '#d97706',
    blue: '#2563eb',
    magenta: '#9333ea',
    cyan: '#0891b2',
    white: '#e5e5e5',
    brightBlack: '#71717a',
    brightRed: '#ef4444',
    brightGreen: '#22c55e',
    brightYellow: '#f59e0b',
    brightBlue: '#3b82f6',
    brightMagenta: '#a855f7',
    brightCyan: '#06b6d4',
    brightWhite: '#ffffff',
  },
}

export const TerminalComponent = forwardRef<TerminalHandle, TerminalProps>(function TerminalComponent(
  {
    wsPath,
    title,
    autoConnect = false,
    onConnectionChange,
    sessionId,
    showNewTab = false,
    onCWDChange,
    followTheme = false,
    titleHighlight,
  }: TerminalProps,
  ref,
) {
  const [connected, setConnected] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [maximized, setMaximized] = useState(false)
  // 始终使用暗黑主题，不跟随全局亮色
  const [themeMode, setThemeMode] = useState<'dark' | 'light'>('dark')
  const terminalRef = useRef<HTMLDivElement>(null)
  const xtermRef = useRef<XTerm | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const connectedRef = useRef(false)
  const onCWDChangeRef = useRef(onCWDChange)
  const themeModeRef = useRef(themeMode)

  useEffect(() => { onCWDChangeRef.current = onCWDChange }, [onCWDChange])
  useEffect(() => { themeModeRef.current = themeMode }, [themeMode])

  // Keep xterm on the classic dark palette regardless of global data-theme
  useEffect(() => {
    const mode: 'dark' | 'light' = 'dark'
    themeModeRef.current = mode
    setThemeMode(mode)
    if (xtermRef.current) xtermRef.current.options.theme = XTERM_THEMES[mode]
  }, [followTheme])

  // Expose sendText so the file browser can drive the shell (e.g. cd into a dir)
  useImperativeHandle(ref, () => ({
    sendText: (text: string) => {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(text)
      }
    },
  }), [])

  const initTerminal = useCallback(() => {
    if (!terminalRef.current || xtermRef.current) return

    const terminal = new XTerm({
      theme: XTERM_THEMES[themeModeRef.current],
      fontFamily: 'Consolas, "Courier New", monospace',
      fontSize: 14,
      lineHeight: 1.2,
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback: 10000,
      allowProposedApi: true,
      // Linux shell 输出为 LF（\n），convertEol 让 LF 同时回车，避免每行输出阶梯状错位
      convertEol: true,
    })

    const fitAddon = new FitAddon()
    terminal.loadAddon(fitAddon)
    xtermRef.current = terminal
    fitAddonRef.current = fitAddon

    terminal.open(terminalRef.current)
    setTimeout(() => { fitAddon.fit(); terminal.focus() }, 0)

    terminal.writeln('\x1b[36m═══════════════════════════════════════\x1b[0m')
    terminal.writeln('\x1b[36m  ToShell Interactive Terminal\x1b[0m')
    terminal.writeln('\x1b[36m  点击"连接"按钮开始会话\x1b[0m')
    terminal.writeln('\x1b[36m═══════════════════════════════════════\x1b[0m')
    terminal.writeln('')

    // Buffer for accumulating the current command line
    let inputBuf = ''

    terminal.onData((data) => {
      if (!connectedRef.current || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return

      const code = data.charCodeAt(0)

      // Multi-byte escape sequences (arrows, home, end, etc.) — pass through raw
      if (code === 0x1b && data.length > 1) {
        wsRef.current.send(data)
        return
      }

      if (code === 13) {
        // Enter — send buffered command
        terminal.write('\r\n')
        wsRef.current.send(inputBuf + '\r\n')
        inputBuf = ''
      } else if (code === 127 || code === 8) {
        // Backspace
        if (inputBuf.length > 0) {
          inputBuf = inputBuf.slice(0, -1)
          terminal.write('\b \b')
        }
      } else if (code === 3) {
        // Ctrl+C — clear buffer, send interrupt
        terminal.write('^C\r\n')
        inputBuf = ''
        wsRef.current.send('\x03')
      } else if (code >= 32 && code < 127) {
        // Printable ASCII — echo locally + buffer
        inputBuf += data
        terminal.write(data)
      }
      // Other control chars: ignore (don't send, don't echo)
    })

    const handleResize = () => fitAddon.fit()
    window.addEventListener('resize', handleResize)
    return () => {
      window.removeEventListener('resize', handleResize)
      if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    }
  }, [])

  useEffect(() => { initTerminal() }, [initTerminal])

  const connect = useCallback(() => {
    if (!xtermRef.current) return
    setConnecting(true)

    const token = localStorage.getItem('toshell-token')
    const fullUrl = wsPath.startsWith('ws')
      ? wsPath + `?token=${encodeURIComponent(token || '')}`
      : `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}${wsPath}?token=${encodeURIComponent(token || '')}`

    const ws = new WebSocket(fullUrl)
    wsRef.current = ws

    ws.onopen = () => {
      setConnected(true)
      connectedRef.current = true
      setConnecting(false)
      xtermRef.current?.focus()
      onConnectionChange?.(true)
    }
    ws.onmessage = (event) => {
      let data: string = event.data
      // CWD marker message from server: \x00CWD\x00<dir> — route to onCWDChange
      if (data.startsWith('\x00CWD\x00')) {
        onCWDChangeRef.current?.(data.slice(5))
        return
      }
      data = data.replace(/\x1b\]0;[^\x07\x1b]*(?:\x07|\x1b\\)/g, '')
      xtermRef.current?.write(data)
    }
    ws.onerror = () => {
      xtermRef.current?.writeln('\x1b[31m[ 连接错误 ]\x1b[0m')
      setConnected(false); connectedRef.current = false; setConnecting(false)
      onConnectionChange?.(false)
    }
    ws.onclose = (event) => {
      xtermRef.current?.writeln(`\r\n\x1b[33m[ 断开: code=${event.code} ]\x1b[0m`)
      setConnected(false); connectedRef.current = false; setConnecting(false)
      onConnectionChange?.(false)
    }
  }, [wsPath, onConnectionChange])

  const disconnect = useCallback(() => {
    if (wsRef.current) { wsRef.current.close(); wsRef.current = null }
    setConnected(false); connectedRef.current = false
    onConnectionChange?.(false)
  }, [onConnectionChange])

  const clear = () => xtermRef.current?.clear()
  const toggleMaximize = () => setMaximized((v) => !v)

  // 状态栏标题：titleHighlight 指定的片段（如主机名）单独高亮着色
  const renderTitle = () => {
    if (!title) return 'Terminal'
    if (!titleHighlight || !title.includes(titleHighlight)) return title
    const idx = title.indexOf(titleHighlight)
    return (
      <>
        {title.slice(0, idx)}
        <span className="terminal-title-highlight">{titleHighlight}</span>
        {title.slice(idx + titleHighlight.length)}
      </>
    )
  }

  useEffect(() => {
    if (autoConnect) connect()
    return () => { if (wsRef.current) { wsRef.current.close(); wsRef.current = null } }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Re-fit terminal when maximized toggles
  useEffect(() => {
    if (fitAddonRef.current) {
      setTimeout(() => fitAddonRef.current!.fit(), 50)
    }
  }, [maximized])

  return (
    <div className={`terminal-component ${maximized ? 'terminal-maximized' : ''} ${followTheme ? (themeMode === 'light' ? 'terminal-light' : 'terminal-dark') : ''}`}>
      {/* Status Bar */}
      <div className="terminal-status-bar">
        <span className="terminal-title">{renderTitle()}</span>
        <div className="terminal-actions">
          <span className={`terminal-status ${connected ? 'connected' : 'disconnected'}`}>
            {connecting ? (
              <><Loader2 size={14} className="spin" /> 连接中</>
            ) : connected ? (
              <><Wifi size={14} /> 已连接</>
            ) : (
              <><WifiOff size={14} /> 断开</>
            )}
          </span>
          {!connected ? (
            <button className="term-btn connect-btn" onClick={connect} disabled={connecting}>
              {connecting ? '连接中...' : '连接'}
            </button>
          ) : (
            <button className="term-btn disconnect-btn" onClick={disconnect}>断开</button>
          )}
          <button className="term-btn" onClick={clear} title="清屏">
            <Trash2 size={14} />
          </button>
          {showNewTab && sessionId && (
            <button className="term-btn" onClick={() => window.open(`/shell/${sessionId}`, '_blank')} title="在新标签页打开">
              <ExternalLink size={14} />
            </button>
          )}
          <button className="term-btn" onClick={toggleMaximize} title={maximized ? '还原' : '最大化'}>
            {maximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
        </div>
      </div>

      {/* Terminal Container */}
      <div className="terminal-container" ref={terminalRef} />
    </div>
  )
})

// Styles in ./Terminal.css - import in your entry point or component usage
