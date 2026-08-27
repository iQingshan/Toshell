import { useState, useEffect, useRef } from 'react'
import { Send, Sparkles, Bot, User, Wrench, RefreshCw, AlertTriangle, Trash2, ListOrdered, Play, Users, ShieldCheck, ShieldX, Timer } from 'lucide-react'
import { copilotApi, sessionApi, taskApi } from '../api'
import type { Playbook, PlaybookRun, ConsentReq } from '../api'
import type { Session } from '../types'
import { useCopilotStore } from '../stores/copilotStore'
import type { CopilotMsg } from '../stores/copilotStore'
import { markdown } from '../utils/markdown'
import './Copilot.css'

/** AI 副驾驶：LLM 聊天面板（工具调用轨迹可视化，会话记录跨页面保留） */
export function Copilot() {
  const messages = useCopilotStore((s) => s.messages)
  const addMessage = useCopilotStore((s) => s.addMessage)
  const clearMessages = useCopilotStore((s) => s.clearMessages)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<{ enabled: boolean; model: string; consent_mode?: string } | null>(null)
  const [showTraces, setShowTraces] = useState<Record<number, boolean>>({})
  const bottomRef = useRef<HTMLDivElement>(null)
  const busyRef = useRef(false)
  busyRef.current = busy
  // 剧本化面板状态
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [selPlaybook, setSelPlaybook] = useState('')
  const [selSession, setSelSession] = useState('')
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  // 审批弹窗（normal 权限模式：影响会话的操作需用户确认）
  const [pendingConsents, setPendingConsents] = useState<ConsentReq[] | null>(null)
  const [consentBusy, setConsentBusy] = useState(false)
  // 两侧信息面板：最近任务
  const [sideTasks, setSideTasks] = useState<{ id: number; task_type: string; command: string; status: string; created_at: string }[]>([])
  // 追加去重与状态跟踪：只对本会话观察到 running→终态转变的 run 追加一次分析，
  // 忽略历史已完成 run，避免历史剧本刷屏/重复回复。
  const sawRunningRef = useRef<Set<string>>(new Set())      // 本会话见过 running 的 run
  const pendingRef = useRef<Map<string, number>>(new Map()) // 已启用 AI 但分析未就绪的轮询计数
  const analyzedBatchRef = useRef<Set<string>>(new Set())   // 已按触发批次分析过（同批 run 合一，每次触发给一条）
  // 基线：首次轮询时已存在的 run（页面打开前的历史任务）记为历史，忽略；
  // 之后新出现的 run（含快速完成/由 AI 触发，未见其 running）也会给建议。
  const baselineRef = useRef<Set<string> | null>(null)
  // 批次键：同一次触发（delegate 多会话）共用一个 batch_id，故同批 run 聚合成一条；
  // 不同批次各自给一条，避免"同剧本第二次执行不再出建议"。
  const batchKey = (run: PlaybookRun) => run.batch_id || run.id

  const isTerminal = (st: string) => st === 'completed' || st === 'failed' || st === 'aborted'

  // 无 AI 分析时的兜底：用步骤结果拼一版可读摘要（短，不刷屏）
  const buildStepSummary = (run: PlaybookRun) => {
    const name = playbooks.find(p => p.id === run.playbook)?.name || run.playbook
    const ok = run.results.filter(s => s.status === 'completed').length
    let s = `🎬 任务「${name}」已完成（${ok}/${run.results.length} 步成功，会话 ${run.session_id}），下一步建议：\n`
    run.results.forEach((st, i) => {
      const icon = st.status === 'completed' ? '✅' : st.status === 'failed' ? '❌' : st.status === 'skipped' ? '⏭️' : '⏳'
      s += `${icon} ${i + 1}. ${st.name}${st.output ? '：' + st.output.slice(0, 50) : ''}\n`
    })
    return s
  }

  useEffect(() => { loadStatus() }, [])
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages, busy])

  const loadStatus = async () => {
    try {
      const res = await copilotApi.status()
      setStatus(res.data)
    } catch { setStatus({ enabled: false, model: '' }) }
  }

  // 加载剧本列表 + 会话列表（剧本面板用）
  const loadPlaybooks = async () => {
    try {
      const [pbRes, sessRes] = await Promise.all([
        copilotApi.playbooks().catch(() => ({ data: { playbooks: [] } })),
        sessionApi.list().catch(() => ({ data: { sessions: [] } })),
      ])
      setPlaybooks(pbRes?.data?.playbooks || [])
      const s = sessRes?.data?.sessions || []
      setSessions(s)
      if (!selSession && s.length > 0) setSelSession(s[0].id)
      if (!selPlaybook && pbRes?.data?.playbooks?.length > 0) setSelPlaybook(pbRes.data.playbooks[0].id)
    } catch (e) { console.error('load playbooks failed:', e) }
  }
  useEffect(() => { loadPlaybooks() }, [])

  // 两侧信息面板：右侧「最近任务」概览（每 8s 刷新，静默）
  useEffect(() => {
    const load = async () => {
      try {
        const r = await taskApi.list()
        const t = (r?.data as any)?.tasks || []
        setSideTasks(Array.isArray(t) ? t.slice(0, 8) : [])
      } catch { /* 静默 */ }
    }
    load()
    const iv = setInterval(load, 8000)
    return () => clearInterval(iv)
  }, [])

  // 常驻轮询任务运行状态（3s）：无论手动点「执行」还是 AI 通过 delegate 触发的任务，
  // 都实时同步到任务面板，并在 running→终态后给【一条】AI 下一步建议。
  useEffect(() => {
    const load = async () => {
      try {
        const res = await copilotApi.playbookRuns()
        const list = res?.data?.runs || []
        setRuns(list)
        // 收集 run：首次轮询把已存在的 run 记为历史基线，忽略；此后任何"新出现的 run"
        //（含快速完成、由 AI 触发且未见其 running）进入处理，避免漏掉建议。
        if (baselineRef.current === null) {
          baselineRef.current = new Set(list.map((r) => r.id))
        }
        const groups = new Map<string, PlaybookRun[]>()
        list.forEach((run) => {
          if (baselineRef.current!.has(run.id)) return // 页面打开前的历史 run：忽略
          if (run.status === 'running') { sawRunningRef.current.add(run.id); return }
          if (!isTerminal(run.status)) return
          const key = batchKey(run)
          if (!groups.has(key)) groups.set(key, [])
          groups.get(key)!.push(run)
        })
        // 逐批次聚合：同批 run 全部完成后给【一条】汇总下一步建议；不同批次各给一条
        for (const [bk, runs] of groups) {
          const key = 'b:' + bk
          if (analyzedBatchRef.current.has(key)) continue
          if (!runs.every(r => isTerminal(r.status))) continue
          const pbName = playbooks.find(p => p.id === runs[0].playbook)?.name || runs[0].playbook
          const aiReady = runs.some(r => r.analysis)
          if (aiReady) {
            const parts = runs.map(r => r.analysis
              ? `【${pbName} · 会话 ${r.session_id}】\n${r.analysis}`
              : buildStepSummary(r))
            addMessage({ role: 'assistant', content: `📋 任务「${pbName}」执行完成，AI 下一步建议：\n\n${parts.join('\n\n—\n\n')}` })
            analyzedBatchRef.current.add(key)
            pendingRef.current.delete(key)
            continue
          }
          if (!status?.enabled) {
            // AI 未启用：直接用结果摘要给一条
            const parts = runs.map(r => buildStepSummary(r))
            addMessage({ role: 'assistant', content: parts.length === 1 ? parts[0] : `📋 任务「${pbName}」已完成：\n\n${parts.join('\n\n')}` })
            analyzedBatchRef.current.add(key)
            pendingRef.current.delete(key)
            continue
          }
          // 已启用 AI 但分析尚未生成：继续等，超限兜底用结果摘要给一条
          const n = (pendingRef.current.get(key) || 0) + 1
          pendingRef.current.set(key, n)
          if (n >= 8) {
            const parts = runs.map(r => buildStepSummary(r))
            addMessage({ role: 'assistant', content: parts.length === 1 ? parts[0] : `📋 任务「${pbName}」已完成：\n\n${parts.join('\n\n')}` })
            analyzedBatchRef.current.add(key)
            pendingRef.current.delete(key)
          }
        }
      } catch { /* 轮询失败静默，下轮重试 */ }
    }
    load()
    const iv = setInterval(load, 3000)
    return () => clearInterval(iv)
  }, [playbooks, addMessage, status])

  const runSelectedPlaybook = async () => {
    if (!selPlaybook || !selSession) return
    try {      await copilotApi.runPlaybook(selPlaybook, selSession)
      addMessage({ role: 'assistant', content: `已启动任务「${playbooks.find(p => p.id === selPlaybook)?.name || selPlaybook}」→ 会话 ${selSession}，执行中...` })
    } catch (e: any) {
      addMessage({ role: 'assistant', content: '启动任务失败: ' + (e?.response?.data?.error || e.message), error: true })
    }
  }

  const send = async () => {
    const text = input.trim()
    if (!text || busyRef.current) return
    setInput('')
    const userMsg: CopilotMsg = { role: 'user', content: text }
    addMessage(userMsg)
    setBusy(true)
    try {
      // 用 store 最新消息构造历史（避免闭包捕获过期 state）。
      // 上下文压缩：只保留最近 14 条、每条截断到 1600 字符，控制 token 避免无限膨胀与超时。
      const latest = useCopilotStore.getState().messages
      const trunc = (s: string, n = 1600) => (s && s.length > n ? s.slice(0, n) + '…' : (s || ''))
      let history = latest.map((m) => ({ role: m.role, content: trunc(m.content) }))
      if (history.length > 14) history = history.slice(-14)
      const res = await copilotApi.chat(history)
      const data = res.data
      if (data.pending_consents && data.pending_consents.length > 0) {
        // normal 权限模式：影响会话的操作需用户确认 → 追加提示并弹出审批
        addMessage({ role: 'assistant', content: data.reply || '✋ 需要你确认后才继续执行下列操作。', traces: data.traces })
        setPendingConsents(data.pending_consents)
      } else {
        addMessage({ role: 'assistant', content: data.reply || '(空回复)', traces: data.traces })
      }
    } catch (e: any) {
      const errText = e?.response?.data?.error || (e instanceof Error ? e.message : String(e))
      addMessage({ role: 'assistant', content: '调用失败: ' + errText, error: true })
    } finally {
      setBusy(false)
    }
  }

  // 处理一次审批决定：allow→执行，deny→跳过；然后追加助手最终回复（可能又有待确认项）
  const handleConsent = async (token: string, decision: 'allow' | 'deny') => {
    setConsentBusy(true)
    try {
      const res = await copilotApi.consent(token, decision)
      const data = res.data
      if (data.pending_consents && data.pending_consents.length > 0) {
        addMessage({ role: 'assistant', content: data.reply || '✋ 还有操作需要你确认。', traces: data.traces })
        setPendingConsents(data.pending_consents)
      } else {
        addMessage({ role: 'assistant', content: data.reply || '(已完成)', traces: data.traces })
        setPendingConsents(null)
      }
    } catch (e: any) {
      const errText = e?.response?.data?.error || (e instanceof Error ? e.message : String(e))
      addMessage({ role: 'assistant', content: '审批处理失败: ' + errText, error: true })
      setPendingConsents(null)
    } finally {
      setConsentBusy(false)
    }
  }

  const toggleTrace = (idx: number) => setShowTraces((t) => ({ ...t, [idx]: !t[idx] }))

  const suggestions = [
    '列出所有活跃会话',
    '查询情报库中的账号信息',
    '给我一个 Windows 会话的攻击建议',
  ]

  return (
    <div className="copilot-page">
      <div className="copilot-header">
        <div className="copilot-title">
          <Sparkles size={20} />
          <span>AI 副驾驶</span>
          {status?.enabled ? (
            <span className="copilot-badge ok">已连接 · {status.model}</span>
          ) : (
            <span className="copilot-badge off">未配置</span>
          )}
          {status?.consent_mode === 'normal' && (
            <span className="copilot-badge guard" title="影响会话的操作执行前需你同意（任务流除外）。可在 configs/server.yaml 的 ai.consent_mode 调整">🛡 正常模式·需确认</span>
          )}
        </div>
        {!status?.enabled && (
          <div className="copilot-notice">
            <AlertTriangle size={14} />
            在「设置 → AI 副驾驶」中填写 API 端点/密钥/模型后启用
          </div>
        )}
        {messages.length > 0 && (
          <button className="copilot-clear" onClick={clearMessages} title="清空对话记录">
            <Trash2 size={14} /> 清空
          </button>
        )}
      </div>

      <div className="copilot-body">
        <aside className="side-panel side-left">
          <div className="side-title"><Users size={14} /> 在线会话</div>
          <div className="side-list">
            {sessions.length === 0 ? <div className="side-empty">暂无会话</div> :
              sessions.map((s) => (
                <div key={s.id} className={`side-item ${s.status === 'active' ? 'on' : 'off'}`}
                  onClick={() => setInput(`分析会话 ${s.hostname || s.id} 的上下文并给出下一步建议`)}>
                  <span className={`side-dot ${s.status === 'active' ? 'on' : 'off'}`} />
                  <div className="side-item-col">
                    <span className="side-item-main">{s.hostname || s.id}</span>
                    <span className="side-item-sub">{s.os} · {s.username}</span>
                  </div>
                </div>
              ))}
          </div>
        </aside>

        <div className="copilot-main">

      <div className="copilot-chat">
        {messages.length === 0 && (
          <div className="copilot-empty">
            <Bot size={40} />
            <p>我是 ToShell 副驾驶，可以帮你分析会话、查询情报、下发任务。</p>
            <div className="copilot-suggests">
              {suggestions.map((s) => (
                <button key={s} onClick={() => { setInput(s) }}>{s}</button>
              ))}
            </div>
          </div>
        )}

        {messages.map((m, i) => (
          <div key={i} className={`copilot-msg ${m.role}${m.error ? ' error' : ''}`}>
            <div className="copilot-avatar">
              {m.role === 'user' ? <User size={16} /> : <Bot size={16} />}
            </div>
            <div className="copilot-bubble">
              {m.role === 'user' ? (
                <div className="copilot-content">{m.content}</div>
              ) : (
                <div className="copilot-content" dangerouslySetInnerHTML={{ __html: markdown(m.content) }} />
              )}
              {m.traces && m.traces.length > 0 && (
                <div className="copilot-traces">
                  <button className="trace-toggle" onClick={() => toggleTrace(i)}>
                    <Wrench size={13} /> 工具调用 ({m.traces.length})
                    {showTraces[i] ? ' ▾' : ' ▸'}
                  </button>
                  {showTraces[i] && (
                    <div className="trace-list">
                      {m.traces.map((t, j) => (
                        <div key={j} className="trace-item">
                          <div className="trace-name">
                            <Wrench size={12} /> {t.name}
                            {t.args && Object.keys(t.args).length > 0 && (
                              <code>{JSON.stringify(t.args)}</code>
                            )}
                          </div>
                          {t.error && <div className="trace-error">error: {t.error}</div>}
                          {t.result && (
                            <pre className="trace-result">{t.result.length > 800 ? t.result.slice(0, 800) + '...' : t.result}</pre>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}

        {busy && (
          <div className="copilot-msg assistant">
            <div className="copilot-avatar"><Bot size={16} /></div>
            <div className="copilot-bubble copilot-thinking">
              <RefreshCw size={14} className="spin" /> 思考中...
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* 任务化：一键攻击链 + 子代理 */}
      <div className="playbook-panel">
        <div className="playbook-bar">
          <div className="playbook-title">
            <ListOrdered size={16} />
            <span>任务</span>
          </div>
          <select value={selPlaybook} onChange={(e) => setSelPlaybook(e.target.value)} className="playbook-select">
            {playbooks.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <div className="playbook-title">
            <Users size={16} />
            <span>会话</span>
          </div>
          <select value={selSession} onChange={(e) => setSelSession(e.target.value)} className="playbook-select">
            {sessions.map((s) => <option key={s.id} value={s.id}>{s.hostname}</option>)}
          </select>
          <button className="playbook-run" onClick={runSelectedPlaybook} disabled={!selPlaybook || !selSession}>
            <Play size={14} /> 执行
          </button>
        </div>

        {runs.length > 0 && (
          <div className="playbook-runs">
            {runs.slice(0, 3).map((run) => (
              <div key={run.id} className={`playbook-run-card st-${run.status}`}>
                <div className="playbook-run-head">
                  <span className="playbook-run-name">{playbooks.find(p => p.id === run.playbook)?.name || run.playbook}</span>
                  <span className={`playbook-run-status st-${run.status}`}>{run.status}</span>
                </div>
                <div className="playbook-run-progress">
                  {run.results.map((st, i) => (
                    <span key={i} className={`pb-step st-${st.status}`} title={`${st.name}: ${st.status}`}>
                      {i + 1}
                    </span>
                  ))}
                </div>
                <div className="playbook-run-session">会话 {run.session_id}</div>
                {run.results.length > 0 && (
                  <div className="playbook-run-steps">
                    {run.results.map((st, i) => (
                      <div key={i} className={`pb-step-row st-${st.status}`} title={st.output || st.error || st.status}>
                        <span className="pb-step-dot">{st.status === 'completed' ? '✅' : st.status === 'failed' ? '❌' : st.status === 'skipped' ? '⏭️' : '⏳'}</span>
                        <span className="pb-step-name">{st.name}</span>
                        <span className="pb-step-out">{st.output ? st.output.slice(0, 60) : (st.error || st.status)}</span>
                      </div>
                    ))}
                  </div>
                )}
                {run.analysis && (
                  <details className="playbook-run-analysis">
                    <summary className="pb-analysis-label">🤖 AI 分析 · 点击展开完整建议</summary>
                    <div className="pb-analysis-text">{run.analysis}</div>
                  </details>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="copilot-inputbar">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() } }}
          placeholder="询问会话状态、查询情报、下发任务…"
          disabled={busy || !status?.enabled}
        />
        <button onClick={send} disabled={busy || !input.trim() || !status?.enabled} title="发送">
          <Send size={18} />
        </button>
      </div>

        </div>

        <aside className="side-panel side-right">
          <div className="side-title"><Timer size={14} /> 最近任务</div>
          <div className="side-list">
            {sideTasks.length === 0 ? <div className="side-empty">暂无任务</div> :
              sideTasks.map((t) => (
                <div key={t.id} className="side-item">
                  <span className={`task-state ${t.status === 'completed' ? 'ok' : t.status === 'failed' || t.status === 'timeout' ? 'err' : 'run'}`} />
                  <div className="side-item-col">
                    <span className="side-item-main">{t.command || t.task_type || `#${t.id}`}</span>
                    <span className="side-item-sub">{t.task_type} · #{t.id}</span>
                  </div>
                  <span className="side-item-status">{t.status}</span>
                </div>
              ))}
          </div>
        </aside>
      </div>

      {pendingConsents && pendingConsents.length > 0 && (
        <div className="consent-overlay">
          <div className="consent-card">
            <div className="consent-head"><ShieldCheck size={18} /> 操作需你确认</div>
            <div className="consent-desc">副驾驶请求执行以下影响目标会话的操作（正常权限模式，任务流除外）：</div>
            <div className="consent-list">
              {pendingConsents.map((c) => (
                <div key={c.token} className="consent-item">
                  <div className="consent-tool"><Wrench size={13} /> {c.tool}{c.desc ? <span className="consent-desc-sm">{c.desc}</span> : null}</div>
                  {c.args && Object.keys(c.args).length > 0 && <code className="consent-args">{JSON.stringify(c.args)}</code>}
                </div>
              ))}
            </div>
            <div className="consent-actions">
              <button className="consent-btn deny" disabled={consentBusy} onClick={() => handleConsent(pendingConsents[0].token, 'deny')}><ShieldX size={14} /> 拒绝</button>
              <button className="consent-btn allow" disabled={consentBusy} onClick={() => handleConsent(pendingConsents[0].token, 'allow')}><ShieldCheck size={14} /> 允许</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
