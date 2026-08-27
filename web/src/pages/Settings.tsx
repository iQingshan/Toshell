import { useState, useEffect } from 'react'
import { Save, User, Bell, Shield, Server, RefreshCw, Sparkles } from 'lucide-react'
import { settingsApi } from '../api'
import './Settings.css'

interface SettingsData {
  general: Record<string, any>
  listener: Record<string, any>
  implant: Record<string, any>
  notifications: Record<string, any>
  security: Record<string, any>
  ai: Record<string, any>
  new_password?: string // 仅前端草稿，不随分组提交
}

type SettingsGroup = 'general' | 'listener' | 'implant' | 'notifications' | 'security' | 'ai'

const EMPTY: SettingsData = {
  general: {},
  listener: {},
  implant: {},
  notifications: {},
  security: {},
  ai: {},
}

/** 设置页：真实读写运行时配置（/api/v1/settings），保存后热生效 */
export function Settings() {
  const [activeTab, setActiveTab] = useState('general')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [testResult, setTestResult] = useState<{ ok: boolean; status_code: number; response: string } | null>(null)

  // 表单草稿
  const [draft, setDraft] = useState<SettingsData>(EMPTY)

  const load = async () => {
    setLoading(true)
    setMsg(null)
    try {
      const res = await settingsApi.get()
      setDraft(JSON.parse(JSON.stringify(res.data)))
    } catch (e) {
      setMsg({ kind: 'err', text: '加载设置失败: ' + (e instanceof Error ? e.message : String(e)) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const setField = (group: SettingsGroup, key: string, value: any) => {
    setDraft((prev) => ({ ...prev, [group]: { ...(prev[group] as Record<string, any>), [key]: value } }))
  }

  /** 提交指定分组的改动（只发送该分组） */
  const save = async (group: SettingsGroup) => {
    setSaving(true)
    setMsg(null)
    try {
      const payload: Record<string, any> = { ...(draft[group] as Record<string, any>) }
      // 账户 tab：新密码并入 security 分组提交
      if (group === 'security' && draft.new_password) {
        payload.new_password = draft.new_password
      }
      // 保存成功后提示
      await settingsApi.save({ [group]: payload })
      setDraft((p) => ({ ...p, new_password: '' }))
      // 重新拉取最新配置
      await load()
      const label = ({ ai: 'AI 副驾驶', listener: '监听器', implant: '植入端', notifications: '通知', security: '安全' } as Record<string, string>)[group] || group
      setMsg({ kind: 'ok', text: `✓ 已保存 ${label} 配置` })
    } catch (e: any) {
      const errText = e?.response?.data?.error || (e instanceof Error ? e.message : String(e))
      setMsg({ kind: 'err', text: '保存失败: ' + errText })
    } finally {
      setSaving(false)
    }
  }

  const num = (v: any): number => (typeof v === 'number' ? v : Number(v) || 0)

  /** 发送测试通知到当前填写的 webhook（不改动已保存配置） */
  const testWebhook = async () => {
    setSaving(true)
    setTestResult(null)
    try {
      const res = await settingsApi.testWebhook({
        url: draft.notifications.url || '',
        content: draft.notifications.content || '',
        format: draft.notifications.format || 'auto',
        secret: draft.notifications.secret || '',
      })
      setTestResult(res.data)
    } catch (e: any) {
      const errText = e?.response?.data?.error || (e instanceof Error ? e.message : String(e))
      setTestResult({ ok: false, status_code: 0, response: errText })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="settings-page">
      <div className="settings-sidebar">
        {([
          ['general', '常规设置', Server],
          ['security', '安全设置', Shield],
          ['account', '账户设置', User],
          ['notifications', '通知设置', Bell],
          ['ai', 'AI 副驾驶', Sparkles],
        ] as const).map(([key, label, Icon]) => (
          <button
            key={key}
            className={`settings-tab ${activeTab === key ? 'active' : ''}`}
            onClick={() => { setActiveTab(key); setMsg(null) }}
          >
            <Icon size={18} />
            {label}
          </button>
        ))}
      </div>

      <div className="settings-content">
        {loading ? (
          <div className="settings-loading"><RefreshCw size={18} className="spin" /> 加载配置...</div>
        ) : (
          <>
            {msg && (
              <div className={`settings-msg ${msg.kind}`}>
                {msg.text}
                {msg.kind === 'ok' && <button className="settings-msg-close" onClick={() => setMsg(null)}>×</button>}
              </div>
            )}

            {/* ── 常规：监听器 + 植入默认参数 ── */}
            {activeTab === 'general' && (
              <div className="settings-section">
                <h2>常规设置</h2>
                <div className="settings-group">
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>监听器启用</label>
                      <span className="setting-desc">默认 C2 监听器开关</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.listener.enabled} onChange={(e) => setField('listener', 'enabled', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>监听地址</label>
                      <span className="setting-desc">绑定主机与端口（改动需重启监听器）</span>
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input type="text" value={draft.listener.host || ''} onChange={(e) => setField('listener', 'host', e.target.value)} className="setting-input" style={{ width: 140 }} />
                      <input type="number" value={num(draft.listener.port)} onChange={(e) => setField('listener', 'port', Number(e.target.value))} className="setting-input" style={{ width: 100 }} />
                    </div>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>公网地址</label>
                      <span className="setting-desc">生成载荷时展示/使用的对外地址</span>
                    </div>
                    <input type="text" value={draft.listener.public_host || ''} onChange={(e) => setField('listener', 'public_host', e.target.value)} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>流量拟态模板</label>
                      <span className="setting-desc">HTTP 监听器响应整形（热生效）</span>
                    </div>
                    <select className="setting-input" value={draft.listener.mimicry_profile || 'cdn'} onChange={(e) => setField('listener', 'mimicry_profile', e.target.value)}>
                      <option value="cdn">cdn（静态资源/CDN）</option>
                      <option value="api">api（REST API）</option>
                      <option value="stream">stream（视频流/m3u8）</option>
                    </select>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>域前置拟态域名</label>
                      <span className="setting-desc">HTTPS 轮询通道的 TLS SNI + HTTP Host（热生效，示例: cdn.example.com）</span>
                    </div>
                    <input type="text" value={draft.listener.front_domain || ''} onChange={(e) => setField('listener', 'front_domain', e.target.value)} className="setting-input" placeholder="留空 = 不使用域前置" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>监听器伪装网站</label>
                      <span className="setting-desc">HTTP 监听器对探测请求反向代理到该网站（热生效，示例: https://www.example.com）</span>
                    </div>
                    <input type="text" value={draft.listener.mimicry_site || ''} onChange={(e) => setField('listener', 'mimicry_site', e.target.value)} className="setting-input" placeholder="留空 = 使用静态拟态模板" />
                  </div>
                </div>

                <h2>植入端默认参数（影响后续构建）</h2>
                <div className="settings-group">
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>心跳间隔(秒)</label>
                      <span className="setting-desc">默认心跳/轮询间隔</span>
                    </div>
                    <input type="number" value={num(draft.implant.interval)} onChange={(e) => setField('implant', 'interval', Number(e.target.value))} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>抖动(%)</label>
                      <span className="setting-desc">心跳间隔随机抖动 0-100</span>
                    </div>
                    <input type="number" min={0} max={100} value={num(draft.implant.jitter)} onChange={(e) => setField('implant', 'jitter', Number(e.target.value))} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>重连退避(秒)</label>
                      <span className="setting-desc">断连后的重连基础等待</span>
                    </div>
                    <input type="number" value={num(draft.implant.retry_wait)} onChange={(e) => setField('implant', 'retry_wait', Number(e.target.value))} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>自杀日期</label>
                      <span className="setting-desc">KillDate (YYYY-MM-DD，留空不启用)</span>
                    </div>
                    <input type="text" value={draft.implant.kill_date || ''} onChange={(e) => setField('implant', 'kill_date', e.target.value)} className="setting-input" placeholder="如 2026-12-31" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>启动随机延迟(秒)</label>
                      <span className="setting-desc">植入端启动后随机休眠 [min, max] 秒再连接，打乱「启动即行为」检测（0 关闭）</span>
                    </div>
                    <div className="setting-inputs">
                      <input type="number" min={0} max={600} value={draft.implant.startup_delay_min !== undefined ? num(draft.implant.startup_delay_min) : ''} onChange={(e) => setField('implant', 'startup_delay_min', Number(e.target.value))} className="setting-input" placeholder="min" />
                      <span>~</span>
                      <input type="number" min={0} max={600} value={draft.implant.startup_delay_max !== undefined ? num(draft.implant.startup_delay_max) : ''} onChange={(e) => setField('implant', 'startup_delay_max', Number(e.target.value))} className="setting-input" placeholder="max" />
                    </div>
                  </div>
                </div>

                <div className="settings-actions">
                  <button className="save-btn" onClick={() => save('listener')} disabled={saving}>
                    <Save size={16} /> {saving ? '保存中...' : '保存监听器设置'}
                  </button>
                  <button className="save-btn" onClick={() => save('implant')} disabled={saving}>
                    <Save size={16} /> {saving ? '保存中...' : '保存植入默认参数'}
                  </button>
                </div>
              </div>
            )}

            {/* ── 安全：认证开关 ── */}
            {activeTab === 'security' && (
              <div className="settings-section">
                <h2>安全设置</h2>
                <div className="settings-group">
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>启用认证</label>
                      <span className="setting-desc">Web 控制台登录认证（热生效）</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.security.auth_enabled} onChange={(e) => setField('security', 'auth_enabled', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>JWT 认证</label>
                      <span className="setting-desc">登录令牌机制</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.security.jwt_enabled} onChange={(e) => setField('security', 'jwt_enabled', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>API Key 认证</label>
                      <span className="setting-desc">接口密钥机制</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.security.api_key_enabled} onChange={(e) => setField('security', 'api_key_enabled', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                </div>
                <div className="settings-actions">
                  <button className="save-btn" onClick={() => save('security')} disabled={saving}>
                    <Save size={16} /> {saving ? '保存中...' : '保存安全设置'}
                  </button>
                </div>
              </div>
            )}

            {/* ── 账户：用户名 + 改密码 ── */}
            {activeTab === 'account' && (
              <div className="settings-section">
                <h2>账户设置</h2>
                <div className="settings-group">
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>用户名</label>
                      <span className="setting-desc">登录用户名（热生效）</span>
                    </div>
                    <input type="text" value={draft.security.admin_username || ''} onChange={(e) => setField('security', 'admin_username', e.target.value)} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>新密码</label>
                      <span className="setting-desc">修改登录密码（≥8 位，保存后立即生效）</span>
                    </div>
                    <input type="password" value={draft.new_password || ''} onChange={(e) => setDraft((p) => ({ ...p, new_password: e.target.value }))} placeholder="输入新密码" className="setting-input" />
                  </div>
                </div>
                <div className="settings-actions">
                  <button className="save-btn" onClick={() => save('security')} disabled={saving}>
                    <Save size={16} /> {saving ? '保存中...' : '保存账户设置'}
                  </button>
                </div>
              </div>
            )}

            {/* ── 通知：webhook ── */}
            {activeTab === 'notifications' && (
              <div className="settings-section">
                <h2>通知设置</h2>
                <div className="settings-group">
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>新会话通知</label>
                      <span className="setting-desc">会话上线时发送 webhook 通知（热生效）</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.notifications.enabled} onChange={(e) => setField('notifications', 'enabled', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>Webhook URL</label>
                      <span className="setting-desc">企业微信/钉钉/飞书/Slack 机器人地址</span>
                    </div>
                    <input type="text" value={draft.notifications.url || ''} onChange={(e) => setField('notifications', 'url', e.target.value)} className="setting-input" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..." />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>内容模板</label>
                      <span className="setting-desc">支持 {`{session_id} {hostname} {username} {os} {arch} {remote_addr} {time}`}</span>
                    </div>
                    <textarea
                      value={draft.notifications.content || ''}
                      onChange={(e) => setField('notifications', 'content', e.target.value)}
                      className="setting-input"
                      style={{ minHeight: 60, resize: 'vertical' }}
                      placeholder="新会话上线: {hostname} ({username}@{os}/{arch}) 来自 {remote_addr}"
                    />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>仅上线通知</label>
                      <span className="setting-desc">只在会话上线时发送</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.notifications.only_online} onChange={(e) => setField('notifications', 'only_online', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>消息格式</label>
                      <span className="setting-desc">钉钉自动用 markdown；其它平台通用 JSON（加签 Secret 请在 server.yaml 的 webhook.secret 配置）</span>
                    </div>
                    <select className="setting-input" value={draft.notifications.format || 'auto'} onChange={(e) => setField('notifications', 'format', e.target.value)}>
                      <option value="auto">auto（按 URL 自动识别）</option>
                      <option value="dingtalk">dingtalk（钉钉 markdown）</option>
                      <option value="generic">generic（通用 JSON）</option>
                    </select>
                  </div>
                </div>
                <div className="settings-actions">
                  <button className="save-btn" onClick={() => save('notifications')} disabled={saving}>
                    <Save size={16} /> {saving ? '保存中...' : '保存通知设置'}
                  </button>
                  <button className="save-btn" onClick={testWebhook} disabled={saving || !draft.notifications.url}>
                    <Bell size={16} /> 发送测试通知
                  </button>
                </div>
                {testResult && (
                  <div className={`settings-msg ${testResult.ok ? 'ok' : 'err'}`}>
                    测试结果: HTTP {testResult.status_code} — {testResult.response}
                    <button className="settings-msg-close" onClick={() => setTestResult(null)}>×</button>
                  </div>
                )}
              </div>
            )}

            {/* ── AI 副驾驶：LLM 配置 ── */}
            {activeTab === 'ai' && (
              <div className="settings-section">
                <h2>AI 副驾驶</h2>
                <div className="settings-group">
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>启用</label>
                      <span className="setting-desc">启用聊天面板（侧边栏「AI 副驾驶」页）</span>
                    </div>
                    <label className="toggle">
                      <input type="checkbox" checked={!!draft.ai.enabled} onChange={(e) => setField('ai', 'enabled', e.target.checked)} />
                      <span className="toggle-slider" />
                    </label>
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>API 端点</label>
                      <span className="setting-desc">OpenAI 兼容 chat/completions 端点，如 https://api.deepseek.com/v1</span>
                    </div>
                    <input type="text" value={draft.ai.base_url || ''} onChange={(e) => setField('ai', 'base_url', e.target.value)} className="setting-input" placeholder="https://api.deepseek.com/v1" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>API Key</label>
                      <span className="setting-desc">LLM 服务商密钥（掩码展示，留空不修改）</span>
                    </div>
                    <input type="password" value={draft.ai.api_key || ''} onChange={(e) => setField('ai', 'api_key', e.target.value)} className="setting-input" placeholder="sk-..." />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>模型</label>
                      <span className="setting-desc">模型名，如 deepseek-chat / gpt-4o-mini</span>
                    </div>
                    <input type="text" value={draft.ai.model || 'deepseek-chat'} onChange={(e) => setField('ai', 'model', e.target.value)} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>超时(秒)</label>
                      <span className="setting-desc">单次 LLM 请求超时</span>
                    </div>
                    <input type="number" min={10} max={300} value={num(draft.ai.timeout) || 60} onChange={(e) => setField('ai', 'timeout', Number(e.target.value))} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>最大工具轮数</label>
                      <span className="setting-desc">模型连续调用工具的上限（防死循环）</span>
                    </div>
                    <input type="number" min={1} max={30} value={num(draft.ai.max_turns) || 8} onChange={(e) => setField('ai', 'max_turns', Number(e.target.value))} className="setting-input" />
                  </div>
                  <div className="setting-item">
                    <div className="setting-info">
                      <label>权限模式</label>
                      <span className="setting-desc">正常模式：影响会话的操作（命令下发/文件/进程/凭据/截屏/隧道/插件等）执行前需你确认，任务流除外；全自动：直接执行</span>
                    </div>
                    <select value={draft.ai.consent_mode || 'auto'} onChange={(e) => setField('ai', 'consent_mode', e.target.value)} className="setting-input">
                      <option value="auto">全自动（默认）</option>
                      <option value="normal">正常模式 · 需确认</option>
                    </select>
                  </div>
                </div>
                <div className="settings-actions">
                  <button className="save-btn" onClick={() => save('ai')} disabled={saving}>
                    <Save size={16} /> {saving ? '保存中...' : '保存 AI 配置'}
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
