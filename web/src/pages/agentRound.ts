/**
 * 「本轮」时间线切片：把跨轮复用的 agent run 的整条 timeline 裁成"本条用户消息触发的那一次执行"。
 *
 * 背景（为什么需要它）：agent run 是**跨轮复用**的——前端首次发送创建 run，之后每条指令都带
 * session_id 续接同一个 run（`agentSessionRef`），所以服务端 `run.Timeline` 会一直累积
 * （上限 400 条）、`run.Objective` 会被最新的 user 消息覆盖。直接把整条 timeline 当"本轮步骤"
 * 渲染，就会出现"新气泡里把前几轮的 🔧/✅ 行又画一遍"的假重复。
 *
 * 切法：用**上一轮结束时观测到的最后一条 timeline 条目的 ts** 作为基线，只保留 ts 严格大于它的条目。
 * 服务端 `RunEvent{Ts,Kind,Text}` 的 Ts 是服务端时钟的毫秒时间戳（`time.Now().UnixMilli()`），
 * 基线值本身就取自服务端同源的 timeline，所以不受客户端时钟偏差影响。
 *
 * 边界为什么用「>」而不是「>=」：
 *   基线 = **上一轮最后一条 timeline 条目**的 ts，它本身属于上一轮，必须排除；用「>=」会把上一轮
 *   的收尾行（如 `✅ xxx`）再画一次，正是要修的重复。
 *   同毫秒风险：只有当本轮第一条 timeline 条目与上一轮最后一条落在同一毫秒时，「>」才会少画那一行。
 *   从上一轮结束到本轮产出第一条 timeline，中间隔着用户输入、POST、以及一次全新的 LLM 往返（≥百毫秒），
 *   实际不可能压进同一毫秒；即便发生，代价也只是"少一行"（可接受），而不是"多画一整轮"（本次的 bug）。
 *
 * 老服务端退化路径：timeline 条目没有 ts（老版本不注入该字段）时，**退化成原行为**（整条取尾部
 * 80 条），保证不崩、不空白；此时"本轮过滤"等价于改动前的显示效果。
 */

/** 服务端 timeline 条目（RunEvent 的展示子集） */
export interface RunTimelineEvent {
  /** 服务端毫秒时间戳；老服务端可能缺失 */
  ts?: number
  kind: string
  text: string
}

/** 本轮基线：发指令那一刻该 run 上"属于上一轮"的 timeline 水位 */
export interface RoundBaseline {
  /** 上一轮结束时观测到的 timeline 条数（仅用于时钟异常时的兜底判定） */
  len: number
  /** 上一轮最后一条 timeline 条目的 ts；0 = 新 run 或没观测到（本轮保留全部条目） */
  ts: number
  /** 本轮用户文本（服务端 Objective 即"最新 user 消息"截断，见 buildRoundActs 注释） */
  objective: string
}

/** 单轮渲染的过程行上限（沿用改动前的 80 条口径，避免超长轮次刷屏） */
export const MAX_ROUND_ROWS = 80

/**
 * 从整条 timeline 里切出"本轮"的条目。
 *
 * @param timeline 服务端返回的完整 timeline（跨轮累积）
 * @param base     本轮基线；undefined = 没观测到基线（例如刷新页面后重新接上），此时保持原行为
 */
export function filterRoundTimeline(
  timeline: RunTimelineEvent[] | undefined | null,
  base: RoundBaseline | undefined,
): RunTimelineEvent[] {
  const tl = Array.isArray(timeline) ? timeline : []
  if (tl.length === 0) return []

  // 无基线 / 基线 ts 为 0（新 run 的第一轮）：整条都属于本轮，沿用原口径取尾部 80 条。
  if (!base || base.ts <= 0) return tl.slice(-MAX_ROUND_ROWS)

  // 老服务端（条目没有 ts）：退回原行为——宁可重复显示过程，也不能空白或崩。
  const hasTs = tl.some((ev) => Number(ev?.ts) > 0)
  if (!hasTs) return tl.slice(-MAX_ROUND_ROWS)

  const round = tl.filter((ev) => (Number(ev?.ts) || 0) > base.ts)
  // 安全网：时间线明明比基线时更长（本轮确实追加了新行），ts 过滤却一条都没留下——只可能是
  // 服务端时钟回跳这类异常。此时退回原行为，避免"本轮过程一行都不显示"的空白假象。
  if (round.length === 0 && base.len > 0 && tl.length > base.len) {
    return tl.slice(-MAX_ROUND_ROWS)
  }
  return round.slice(-MAX_ROUND_ROWS)
}
