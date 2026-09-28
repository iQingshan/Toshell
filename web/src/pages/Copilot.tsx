import { useState, useEffect, useRef } from 'react'
import { Send, Sparkles, Bot, User, Wrench, RefreshCw, AlertTriangle, Trash2, ListOrdered, Play, Users, ShieldCheck, ShieldX, Timer, CircleStop } from 'lucide-react'
import { copilotApi, sessionApi, taskApi, agentApi } from '../api'
import type { Playbook, PlaybookRun, ConsentReq } from '../api'
import type { AgentStreamEvent } from '../api'
import type { Session } from '../types'
import { useCopilotStore } from '../stores/copilotStore'
import type { CopilotMsg, AgentAct } from '../stores/copilotStore'
import { filterRoundTimeline } from './agentRound'
import type { RoundBaseline, RunTimelineEvent } from './agentRound'
import { markdown } from '../utils/markdown'
import './Copilot.css'

/** AI 副驾驶：LLM 聊天面板（工具调用轨迹可视化，会话记录跨页面保留） */
export function Copilot() {
  const messages = useCopilotStore((s) => s.messages)
  const addMessage = useCopilotStore((s) => s.addMessage)
  const replaceLast = useCopilotStore((s) => s.replaceLast)
  const clearMessages = useCopilotStore((s) => s.clearMessages)
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState<{
    enabled: boolean
    model: string
    /** v1.4.0 主键：graded（默认）/ all / off */
    consent_policy?: string
    /** 旧键，后端仍回传，用于老前端兼容 */
    consent_mode?: string
  } | null>(null)
  const [showTraces, setShowTraces] = useState<Record<number, boolean>>({})
  const bottomRef = useRef<HTMLDivElement>(null)
  const busyRef = useRef(false)
  busyRef.current = busy
  // 剧本化面板状态
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [selPlaybook, setSelPlaybook] = useState('')
  const [selSession, setSelSession] = useState('')
  const selSessionRef = useRef('')
  useEffect(() => { selSessionRef.current = selSession }, [selSession])
  const [runs, setRuns] = useState<PlaybookRun[]>([])
  // 审批弹窗（normal 权限模式：影响会话的操作需用户确认）
  const [pendingConsents, setPendingConsents] = useState<ConsentReq[] | null>(null)
  // SSE 缺口提示：服务端用 resync 显式告知"这条流不完整"（缓冲淘汰/运行期丢事件）。
  // 不能静默忽略——否则用户会把"缺一段过程"误当成 agent 真的没做那些事。
  const [streamGap, setStreamGap] = useState<string>('')
  const [consentBusy, setConsentBusy] = useState(false)
  // 两侧信息面板：最近任务
  const [sideTasks, setSideTasks] = useState<{ id: number; task_type: string; command: string; status: string; created_at: string }[]>([])
  // 追加去重与状态跟踪：只对本会话观察到 running→终态转变的 run 追加一次分析，
  // 忽略历史已完成 run，避免历史剧本刷屏/重复回复。
  const sawRunningRef = useRef<Set<string>>(new Set())      // 本会话见过 running 的 run
  const pendingRef = useRef<Map<string, number>>(new Map()) // 已启用 AI 但分析未就绪的轮询计数
  const analyzedBatchRef = useRef<Set<string>>(new Set())   // 已发过「AI 建议」的批次（每条只发一次）
  const fallbackedRef = useRef<Set<string>>(new Set())      // 已发过「兜底摘要」的批次（晚到的 analysis 仍会补发 AI 建议）
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
      if (!selSession && s.length > 0) {
        setSelSession(s[0].id)
        selSessionRef.current = s[0].id
      }
      if (!selPlaybook && pbRes?.data?.playbooks?.length > 0) setSelPlaybook(pbRes.data.playbooks[0].id)
    } catch (e) { console.error('load playbooks failed:', e) }
  }
  useEffect(() => { loadPlaybooks() }, [])

  // 侧栏「在线会话」周期刷新（10s）：新会话上线/掉线即时可见，不点刷新也更新
  useEffect(() => {
    const refresh = async () => {
      try {
        const sessRes = await sessionApi.list()
        const s = sessRes?.data?.sessions || []
        setSessions(s)
        // 无选中会话时自动补选第一个（不清掉已选中的会话）
        if (!selSessionRef.current && s.length > 0) {
          setSelSession(s[0].id)
          selSessionRef.current = s[0].id
        }
      } catch { /* 静默 */ }
    }
    const iv = setInterval(refresh, 10000)
    return () => clearInterval(iv)
  }, [])

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
          if (analyzedBatchRef.current.has(key)) continue // AI 建议已发过，不再重复
          if (!runs.every(r => isTerminal(r.status))) continue
          const pbName = playbooks.find(p => p.id === runs[0].playbook)?.name || runs[0].playbook
          const aiReady = runs.some(r => r.analysis)
          if (aiReady) {
            const parts = runs.map(r => r.analysis
              ? `【${pbName} · 会话 ${r.session_id}】\n${r.analysis}`
              : buildStepSummary(r))
            // 之前可能已发过兜底摘要，这里补发正式 AI 建议（标记来源）
            const prefix = fallbackedRef.current.has(key) ? '📋 任务「' + pbName + '」执行完成，AI 下一步建议（补充）：\n\n' : '📋 任务「' + pbName + '」执行完成，AI 下一步建议：\n\n'
            addMessage({ role: 'assistant', content: prefix + parts.join('\n\n—\n\n') })
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
          // 已启用 AI 但分析尚未生成：等待（上限 30 轮 ≈ 90s，兼容 LLM 慢分析）。
          // 超限先发兜底摘要但不标记 AI 已发——analysis 晚到仍会在后续轮次补发建议。
          const n = (pendingRef.current.get(key) || 0) + 1
          pendingRef.current.set(key, n)
          if (n >= 30 && !fallbackedRef.current.has(key)) {
            const parts = runs.map(r => buildStepSummary(r))
            addMessage({ role: 'assistant', content: parts.length === 1 ? parts[0] : `📋 任务「${pbName}」已完成：\n\n${parts.join('\n\n')}` })
            fallbackedRef.current.add(key)
            pendingRef.current.set(key, 15) // 之后继续小步等待，analysis 到达即补发 AI 建议
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
    // 流式占位：思考中（无正文）
    addMessage({ role: 'assistant', content: '', streaming: true, thinking: true, acts: [] })
    try {
      // 用 store 最新消息构造历史（排除最后一条空的流式占位）
      const latest = useCopilotStore.getState().messages
      const trunc = (s: string, n = 1600) => (s && s.length > n ? s.slice(0, n) + '…' : (s || ''))
      let history = latest
        .filter((m) => !(m.streaming))
        .map((m) => ({ role: m.role, content: trunc(m.content) }))
      if (history.length > 14) history = history.slice(-14)

      // 异步创建/续接 run，立即拿到 run_id（不阻塞）。带 session_id 以保持自主记忆上下文。
      const res = await agentApi.chat(history, agentSessionRef.current || undefined)
      const runId = res.data.run_id
      // 首次创建时记录 session_id（= run_id），后续指令续接到同一记忆
      if (!agentSessionRef.current) agentSessionRef.current = res.data.session_id || runId
      activeRunIdRef.current = runId

      // 本轮基线：发指令那一刻该 run 上"属于上一轮"的 timeline 尾部快照 + 本轮用户文本。
      // 用上一次观测到的快照而不是再 GET 一次：GET 会与已经启动的本轮抢时间（可能把本轮最前面
      // 几行算进基线，反而漏渲染）。新 run / 没观测到过快照时 ts=0，等价于"整条 timeline 都属于本轮"。
      const seen = runTimelineRef.current.get(runId)
      roundBaseRef.current.set(runId, {
        len: seen?.len || 0,
        ts: seen?.ts || 0,
        objective: truncateLine(text, 200),
      })

      // 主路径：轮询 status() 直到终态（绝对可靠，不依赖长连接）。
      // SSE 作为实时增量增强——SSE 断开/失败不影响结论，轮询兜底一定渲染最终结果。
      pollRun(runId)
      setStreamGap('')
      // SSE 作为实时增量增强；断线会自动带 Last-Event-ID 续传（见 api/index.ts 的 streamAgent），
      // shouldContinue 保证用户发了下一轮指令后旧连接不再重连。
      //
      // 续接轮的关键：把本 run 上"已经消费过的最大事件 id"作为**初始水位线**传进去。
      // run 是多轮复用的，每轮都新开一条 SSE：没有水位线时，服务端对运行中的 run 走"从当前开始"
      // （连接建立前已 emit 的增量永久丢失 → 流式正文从半句开始），对已终态的 run 走
      // "回放缓冲尾部 Tail(200)"（条数有上限，本轮最早的一批增量会被吃掉）。带上水位线后统一
      // 变成"只发 seq > 水位线"：既不丢本轮开头，也不可能重发已经消费过的内容。
      const gen = ++roundGenRef.current
      agentApi.events(
        runId,
        (ev) => {
          // 水位线要**先于**"是否属于本轮"的判断推进：即便这条事件来自上一轮的遗留连接，它同样
          // 证明该 run 的 seq 已经走到这里，下一轮的水位线必须跟上，否则下次会把这段又回放一遍。
          noteWaterline(runId, ev.id)
          // 上一轮的遗留连接（含它的自动重连）不得把内容写进本轮气泡——它的消息增量可能属于上一轮。
          if (gen !== roundGenRef.current) return
          handleAgentEvent(ev)
        },
        () => {
          /* SSE 断开时轮询仍在 */
        },
        () => activeRunIdRef.current === runId && gen === roundGenRef.current,
        runWaterlineRef.current.get(runId),
      )
    } catch (e: any) {
      const errText = e?.response?.data?.error || (e instanceof Error ? e.message : String(e))
      // 结束占位，替换为错误
      const latest = useCopilotStore.getState().messages
      let content = '调用失败: ' + errText
      const last = latest[latest.length - 1]
      content = (last?.content || '') + (last?.streaming ? '\n\n' : '') + content
      replaceLast({ role: 'assistant', content, error: true, streaming: false, thinking: false })
      setBusy(false)
    }
  }

  // 当前活跃 run（用于取消/审批）
  const activeRunIdRef = useRef<string | null>(null)
  // 自主记忆会话 ID：首次创建后记录，后续指令续接同一上下文（保持 agent 完整记忆）
  const agentSessionRef = useRef<string | null>(null)

  // ── 跨轮复用 run 的显示层状态（全部按 run_id 分键）────────────────────────
  // agent run 会被多轮指令复用（同一条 session_id 续接同一个 run），由此带来三个"整条 run"与
  // "本轮"口径不一致的坑，这三张表就是用来把两者分开的：
  //   runTimelineRef  : 每次观测到的 timeline 尾部快照（条数 + 最后一条 ts）→ 下一轮基线的来源
  //   roundBaseRef    : 本轮基线（本轮用户文本 + 上一轮 timeline 水位）→ buildActs 据此只切本轮
  //   runWaterlineRef : 本 run 上已经消费过的最大 SSE 事件 id → 下一轮连接的初始水位线
  const runTimelineRef = useRef<Map<string, { len: number; ts: number }>>(new Map())
  const roundBaseRef = useRef<Map<string, RoundBaseline>>(new Map())
  const runWaterlineRef = useRef<Map<string, number>>(new Map())
  // 本轮连接代次：send() 每次自增。上一轮遗留的 SSE 连接（含它自己的自动重连）不得把内容写进本轮气泡。
  const roundGenRef = useRef(0)

  // 记录某 run 的 timeline 尾部快照，作为"下一次 send 时的本轮基线"。
  // 空 timeline 不更新：否则会把已知基线抹成 0，下一轮就会把整条 timeline 当成本轮。
  const rememberTimeline = (runId: string, data: any) => {
    const tl = Array.isArray(data?.timeline) ? data.timeline : []
    if (tl.length === 0) return
    runTimelineRef.current.set(runId, { len: tl.length, ts: Number(tl[tl.length - 1]?.ts) || 0 })
  }

  // 推进某 run 的 SSE 水位线（只增不减）：值是服务端 run 内单调的事件 seq。
  const noteWaterline = (runId: string, id?: number) => {
    if (!id || id <= 0) return
    if (id > (runWaterlineRef.current.get(runId) || 0)) runWaterlineRef.current.set(runId, id)
  }

  // 轮询主路径：稳定拉取 run 状态，直到终态，渲染最终结果。SSE 断连时的可靠兜底。
  const pollRun = async (runId: string) => {
    let attempts = 0
    const maxAttempts = 180 // 180 * 2s = 最长 6 分钟
    const iv = setInterval(async () => {
      attempts++
      if (attempts > maxAttempts || activeRunIdRef.current !== runId) {
        clearInterval(iv)
        setBusy(false)
        return
      }
      try {
        const st = await agentApi.status(runId)
        const data = st.data
        // 记下本轮 timeline 尾部快照：这就是"下一轮"的基线来源（终态那次轮询拿到的就是本轮的收尾快照）
        rememberTimeline(runId, data)
        // 执行过程以「日志行」写入会话气泡：🎯 目标 → 🔧 工具调用 → ✅/❌ 结果
        // （不再用独立的计划/时间线面板，一切都在对话流里；且只渲染**本轮**的行，见 buildActs）
        const acts = buildActs(data, runId)
        if (acts.length > 0) {
          useCopilotStore.getState().setLastActs(acts)
        }
        // 用最新状态增量更新最后一条 assistant 消息：内容
        if (data.reply) {
          useCopilotStore.getState().appendToLast({ role: 'assistant', content: data.reply.replace(/\n{3,}/g, '\n\n'), thinking: false, streaming: true })
        }
        if (data.status === 'done' || data.status === 'error' || data.status === 'awaiting_consent') {
          clearInterval(iv)
          finalizeRun(runId)
        }
      } catch { /* 下次重试 */ }
    }, 2000)
  }

  // buildActs 把 run 状态（**本轮**目标 + **本轮**时间线）整理成会话内联的日志行。
  // 行格式：icon + 文本；tool_start=🔧，tool_result 依内容 ✅/❌/⏭，错误=⚠️。
  //
  // 为什么必须按"本轮"切：run 是跨轮复用的，`data.timeline` 是整条 run 累积的时间线（服务端上限
  // 400 条），直接渲染就会在新气泡里把前几轮的 🔧/✅ 再画一遍（假重复）。切法见 agentRound.ts：
  // 用 send() 时记下的基线（上一轮最后一条 timeline 的 ts）保留 ts 严格更大的条目。
  // 目标同理：服务端 Objective 会被"最新 user 消息"覆盖，但它只在首轮 LLM 返回之后才更新，
  // 续接轮的第一个轮询会读到**上一轮**的目标——所以有基线时直接用本轮发出去的用户文本。
  // 没有基线（页面刷新后重新接上、老服务端没有 ts）时全部退回改动前的行为，不崩不空白。
  const buildActs = (data: any, runId?: string): AgentAct[] => {
    const acts: AgentAct[] = []
    const base = runId ? roundBaseRef.current.get(runId) : undefined
    const objective = base?.objective ? base.objective : data?.objective ? String(data.objective) : ''
    if (objective) {
      acts.push({ i: '🎯', t: truncateLine(objective, 200) })
    }
    const tl: RunTimelineEvent[] = data?.timeline || []
    // 只保留过程行：跳过 final（回复正文单独渲染），thinking 无时间线条目
    for (const ev of filterRoundTimeline(tl, base)) {
      if (ev.kind === 'final') continue
      if (ev.kind === 'tool_start') {
        acts.push({ i: '🔧', t: truncateLine(ev.text, 160) })
      } else if (ev.kind === 'tool_result') {
        const txt = ev.text || ''
        if (txt.startsWith('❌')) acts.push({ i: '❌', t: truncateLine(txt.replace(/^❌\s*/, ''), 200) })
        else if (txt.startsWith('⏭')) acts.push({ i: '⏭', t: truncateLine(txt.replace(/^⏭\s*/, ''), 200) })
        else acts.push({ i: '✅', t: truncateLine(txt.replace(/^✅\s*/, ''), 200) })
      } else if (ev.kind === 'error') {
        acts.push({ i: '⚠️', t: truncateLine(ev.text, 200) })
      } else {
        acts.push({ i: '·', t: truncateLine(ev.text, 200) })
      }
    }
    return acts
  }

  const truncateLine = (s: string, n: number) => (s && s.length > n ? s.slice(0, n) + '…' : (s || ''))

  // 处理一条 SSE 事件：增量渲染到最后一条 assistant 消息。
  //
  // 与轮询的分工（这个分工不能改坏）：
  //   - `tool_start/tool_result` **不**在这里维护：它们由 pollRun 的 buildActs() 从服务端 timeline
  //     统一生成（2s 轮询是权威且稳定的那份数据源），SSE 只负责"别让 thinking 转圈卡住"。
  //     若两边都写，同一行工具日志会被渲染两次——这正是"看起来重复执行了一遍"的另一半来源。
  //   - `message/final/state` 的正文只由 SSE 增量渲染（轮询只在终态用 `reply` 整体替换一次兜底）。
  //
  // 为什么现在的组合既不重复也不丢事件：
  //   重复：① 过程行只有 poll→buildActs 一个来源，且 buildActs 只取**本轮** timeline（基线切分）；
  //         ② SSE 每条连接带跨轮水位线，服务端只发 seq > 水位线 的事件，不会把上一轮缓冲再回放；
  //         ③ 上一轮遗留的连接（含其重连）被本轮代次挡在气泡外，并会被 streamAgent 主动断开。
  //   丢事件：水位线同时消除了"运行中的 run 从当前开始"语义——连接建立前已 emit 的增量会按
  //         `snap.After(lastID)` 补发；真正补不上的缺口仍由服务端 resync 显式告知并拉 run 详情对齐。
  const handleAgentEvent = (ev: AgentStreamEvent) => {
    const s = useCopilotStore.getState()
    switch (ev.event) {
      case 'thinking':
        // 思考阶段：显示为 thinking 标记 + 可选预览
        s.appendToLast({ role: 'assistant', thinking: true, streaming: true })
        break
      case 'message':
        // 正文增量：追加（过滤纯空白增量，避免 LLM 流式输出产生大量空行）
        if (typeof ev.data === 'string') {
          // 跳过纯空白（仅空格/换行）的增量，减少冗余空行
          if (ev.data.length > 0 && ev.data.replace(/\s/g, '') === '') {
            break
          }
          const cur = s.messages[s.messages.length - 1]?.content || ''
          // 折叠连续换行：把 3+ 个连续 \n 压成 2 个（markdown 段落分隔）
          const merged = (cur + ev.data).replace(/\n{3,}/g, '\n\n')
          s.appendToLast({ role: 'assistant', content: merged, thinking: false, streaming: true })
        }
        break
      case 'tool_start':
      case 'tool_result':
        // 工具开始/结果：由 pollRun 的 buildActs() 从服务端 timeline 统一生成内联日志行
        // （2s 轮询即权威且稳定，避免 SSE 与轮询重复/竞争）；这里不再单独维护 traces。
        s.appendToLast({ role: 'assistant', thinking: false, streaming: true })
        break
      case 'final':
        // 最终答复：整体替换（折叠连续空行）
        s.appendToLast({ role: 'assistant', content: (ev.data || '').replace(/\n{3,}/g, '\n\n'), thinking: false, streaming: true })
        break
      case 'consent':
        // 弹出审批
        setPendingConsents([ev.data])
        break
      case 'state':
        // 终态回放：run 已 done/error（尤其连接晚于执行结束），把 reply 渲染出来。
        // 错误静默：轮询 pollRun 才是最终结果来源，SSE 的错误不污染 UI。
        if (ev.data?.done && ev.data?.reply) {
          s.appendToLast({ role: 'assistant', content: ev.data.reply, thinking: false, streaming: false })
        }
        // 无 reply 的 error 不渲染，交给轮询兜底
        break
      case 'error':
        // SSE 错误（如事件通道满/连接断）静默，绝不显示为 network error。
        // 轮询 pollRun 会渲染真正的最终结果/建议。
        break
      case 'resync': {
        // 服务端明确告知"这条事件流有缺口"：events_expired（缓冲淘汰）/ events_dropped
        // （运行期丢事件）。两种都不能静默——把提示显出来，并立刻拉一次 run 详情对齐。
        const reason = String(ev.data?.reason || '')
        const text =
          reason === 'events_expired'
            ? '事件流缺口：要续传的事件已被服务端淘汰（只保留最近一段），过程以轮询结果为准'
            : reason === 'events_dropped'
              ? '事件流缺口：服务端运行期丢过事件，过程以轮询结果为准'
              : '事件流有缺口，过程以轮询结果为准'
        setStreamGap(text)
        const rid = activeRunIdRef.current
        if (rid) {
          void agentApi
            .status(rid)
            .then((st) => {
              // 补一次 run 详情对齐：同样只取本轮行（resync 可能随后又收到事件，基线不变）
              rememberTimeline(rid, st.data)
              const acts = buildActs(st.data, rid)
              if (acts.length > 0) useCopilotStore.getState().setLastActs(acts)
            })
            .catch(() => {
              /* 拉取失败就等下一次轮询 */
            })
        }
        break
      }
      default:
        break
    }
  }

  // 结束最后一条流式消息：主动拉取最终答复作为兜底，确保建议一定显示在会话框
  const finalizeRun = async (runId?: string) => {
    const rid = runId || activeRunIdRef.current
    if (rid) {
      try {
        // 拉最终状态（若 SSE 中途断开/丢失 final，这里兜底渲染建议）
        const st = await agentApi.status(rid)
        // 收尾快照就是本轮的最终 timeline 水位 → 下一次 send 的本轮基线
        rememberTimeline(rid, st.data)
        const reply = st?.data?.reply
        if (reply) {
          useCopilotStore.getState().appendToLast({ role: 'assistant', content: reply, thinking: false, streaming: false })
        }
      } catch { /* 静默：拉取失败不影响已有渲染 */ }
    }
    useCopilotStore.getState().finalizeLast()
    setBusy(false)
    setPendingConsents(null)
    activeRunIdRef.current = null
  }

  // 取消当前 run
  const cancelRun = async () => {
    if (activeRunIdRef.current) {
      try {
        await agentApi.cancel(activeRunIdRef.current)
      } catch { /* 静默 */ }
      finalizeRun()
    }
  }

  // 处理一次审批决定：allow→执行，deny→跳过；然后恢复自主循环（agent run 继续）
  const handleConsent = async (runId: string | null, decision: 'allow' | 'deny') => {
    setConsentBusy(true)
    try {
      const rid = runId || activeRunIdRef.current
      if (!rid) throw new Error('无运行中的 run')
      // 标记当前已在思考/执行中（恢复循环后 SSE 会继续增量）
      useCopilotStore.getState().appendToLast({ role: 'assistant', streaming: true })
      await agentApi.consent(rid, decision)
      setPendingConsents(null)
      setConsentBusy(false)
    } catch (e: any) {
      const errText = e?.response?.data?.error || (e instanceof Error ? e.message : String(e))
      useCopilotStore.getState().appendToLast({ role: 'assistant', content: '\n审批处理失败: ' + errText, error: true, streaming: false })
      setPendingConsents(null)
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
          {status?.consent_policy === 'all' && (
            <span className="copilot-badge guard" title="任何工具（含只读）执行前都需你同意。可在 设置 → AI 副驾驶 的「审批策略」调整">🛡 全部需确认</span>
          )}
          {status?.consent_policy !== 'all' && status?.consent_mode === 'normal' && (
            <span className="copilot-badge guard" title="只读工具直接执行，查询/影响类工具执行前需你同意。可在 设置 → AI 副驾驶 的「审批策略」调整">🛡 分级审批·需确认</span>
          )}
          {status?.consent_policy === 'off' && (
            <span className="copilot-badge off" title="全自动：工具调用不再询问你。可在 设置 → AI 副驾驶 的「审批策略」调整">⚠ 全自动·不询问</span>
          )}
        </div>
        {!status?.enabled && (
          <div className="copilot-notice">
            <AlertTriangle size={14} />
            在「设置 → AI 副驾驶」中填写 API 端点/密钥/模型后启用
          </div>
        )}
        {streamGap && (
          <div className="copilot-notice" title="服务端通过 resync 事件告知这条流不完整">
            <AlertTriangle size={14} />
            {streamGap}
            <button className="copilot-clear" style={{ marginLeft: 8 }} onClick={() => setStreamGap('')}>
              知道了
            </button>
          </div>
        )}
        {messages.length > 0 && (
          <button className="copilot-clear" onClick={clearMessages} title="清空对话记录">
            <Trash2 size={14} /> 清空
          </button>
        )}
      </div>

      {/* Agent 执行过程已内联到会话气泡里（🎯/🔧/✅/❌ 日志行），不再有独立面板 */}

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
                <>
                  {m.thinking && !m.content && (
                    <div className="copilot-thinking-label"><RefreshCw size={13} className="spin" /> 思考中…</div>
                  )}
                  {/* Agent 执行过程：内联日志行（一行目标/执行/结果，带小 icon） */}
                  {m.acts && m.acts.length > 0 && (
                    <div className="agent-acts">
                      {m.acts.map((a, j) => (
                        <div key={j} className={`agent-act ${a.i === '🎯' ? 'act-goal' : a.i === '🔧' ? 'act-tool' : a.i === '❌' ? 'act-fail' : 'act-ok'}`}>
                          <span className="agent-act-icon">{a.i}</span>
                          <span className="agent-act-text">{a.t}</span>
                        </div>
                      ))}
                      {m.streaming && <div className="agent-act act-tool"><span className="agent-act-icon">⏳</span><span className="agent-act-text">执行中…</span></div>}
                    </div>
                  )}
                  {m.content ? (
                    <div className="copilot-content" dangerouslySetInnerHTML={{ __html: markdown(m.content) + (m.streaming ? '<span class="cursor">▍</span>' : '') }} />
                  ) : null}
                  {(!m.acts || m.acts.length === 0) && m.traces && m.traces.length > 0 && (
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
                </>
              )}
            </div>
          </div>
        ))}

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
          placeholder={busy ? 'Agent 正在运行…可继续输入新指令，或点击取消' : '询问会话状态、查询情报、下发任务…'}
          disabled={!status?.enabled}
        />
        {busy ? (
          <button onClick={cancelRun} className="send-btn cancel" disabled={!activeRunIdRef.current} title="取消当前 Agent"><CircleStop size={18} /></button>
        ) : (
          <button onClick={send} disabled={!input.trim() || !status?.enabled} title="发送">
            <Send size={18} />
          </button>
        )}
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
              <button className="consent-btn deny" disabled={consentBusy} onClick={() => handleConsent(null, 'deny')}><ShieldX size={14} /> 拒绝</button>
              <button className="consent-btn allow" disabled={consentBusy} onClick={() => handleConsent(null, 'allow')}><ShieldCheck size={14} /> 允许</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
