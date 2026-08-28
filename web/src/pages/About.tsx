import {
  Shell,
  Github,
  Globe,
  Shield,
  Zap,
  Cpu,
  Server,
  Network,
  Lock,
  Terminal,
  Package,
  Monitor,
  Activity,
  KeyRound,
  Bug,
  FileText,
  Wrench,
  AlertTriangle,
  Satellite,
  GitBranch,
  Video,
  RefreshCw,
  Bot,
  ListOrdered,
} from 'lucide-react'
import './About.css'

const features = [
  {
    icon: <Zap size={22} />,
    title: '轻量高效',
    desc: '采用 Go 语言编写，服务端与植入端均为单二进制文件，资源占用极低；TCP 通道植入端约 3.4MB，秒级启动。',
  },
  {
    icon: <Cpu size={22} />,
    title: '多平台支持',
    desc: '植入端支持 Windows / Linux / macOS，架构覆盖 amd64 / 386 / arm64，可交叉编译生成 exe / dll / raw / shellcode 等格式。',
  },
  {
    icon: <Lock size={22} />,
    title: '加密通信',
    desc: '控制帧 AES-256-GCM 认证加密 + 隧道数据 SM4-GCM 加密（国密算法自研实现），密钥域分离；控制台走 REST API + JWT 认证。',
  },
  {
    icon: <Satellite size={22} />,
    title: '域前置回连',
    desc: '支持 HTTPS 轮询通道 + 自定义 SNI/Host 拟态域名（域前置），服务器部署在 CDN 后即可让目标机出站流量表现为访问合法域名，过白名单出口。',
  },
  {
    icon: <GitBranch size={22} />,
    title: 'Beacon Mesh 中继',
    desc: '多跳中继组网：在线会话可一键升级为中继节点，叶子植入端链式回连，穿透多级网络；中继链路 SM4-GCM 加密。',
  },
  {
    icon: <Video size={22} />,
    title: '实时屏幕流',
    desc: '低频帧率实时屏幕直播，前端支持缩放与全屏；单帧 PNG 快照与超大图 JPEG 自动降级，兼顾清晰度与带宽。',
  },
  {
    icon: <Shield size={22} />,
    title: '内核级对抗',
    desc: '内置 ntdll 脱钩 + ETW 事件抑制（EDR 失明）、BYOVD 驱动加载（内置原厂签名 RTCore64）、PPL 保护清除与杀软击杀。',
  },
  {
    icon: <Monitor size={22} />,
    title: '功能完备',
    desc: '会话管理、载荷构建、文件传输、进程注入、交互 Shell、截图、屏幕流、BOF 插件、持久化、凭据收集、任务调度等完整能力。',
  },
  {
    icon: <Network size={22} />,
    title: '多通道监听',
    desc: 'TCP（二进制帧）/ HTTP(S)（轮询 + 域前置）/ WebSocket / MQTT（内嵌或外部 broker）四种通道；构建时按通道类型自动裁剪代码（transport 条件编译）。',
  },
  {
    icon: <RefreshCw size={22} />,
    title: '配置热更新',
    desc: '设置页真实读写运行时配置，webhook / 流量拟态模板 / 认证信息保存即热生效，无需重启进程；配置文件被外部修改也会自动重载。',
  },
  {
    icon: <Wrench size={22} />,
    title: '老系统兼容',
    desc: '生成 Windows 载荷时自动切换 Go 1.20.14 工具链编译，兼容 Windows 7 / Server 2008 R2 等老系统。',
  },
  {
    icon: <Activity size={22} />,
    title: '审计与运维',
    desc: '登录日志审计、任务统计口径、数据库一键清理脚本，支持大文件分片传输与断点续传；会话上线可推送钉钉/企业微信/飞书等 webhook 通知。',
  },
  {
    icon: <Bot size={22} />,
    title: 'AI 副驾驶',
    desc: '内置 LLM ReAct 智能副驾驶（30+ 工具），自动理解目标会话上下文、连续编排侦察→行动→复盘；支持权限模式（正常模式影响会话操作需确认，任务流除外）与操作审批弹窗。',
  },
  {
    icon: <ListOrdered size={22} />,
    title: '任务流 / 剧本化执行',
    desc: '可编辑任务流模板一键化执行确定性多步链路（信息收集/凭据收集/综合侦察等），跑完自动由 AI 给出结果综述与下一步攻击建议。',
  },
]

const architecture = [
  {
    icon: <Server size={22} />,
    title: 'Team Server',
    desc: '服务端，提供 Web 控制台、REST API、TCP/HTTP C2 监听器与载荷生成，单进程即可运行全部服务。',
  },
  {
    icon: <Monitor size={22} />,
    title: 'Web 控制台',
    desc: '浏览器管理界面，提供会话管理、文件管理、载荷生成、屏幕流、插件管理、登录审计、运行时设置等功能。',
  },
  {
    icon: <Package size={22} />,
    title: 'Implant（植入端）',
    desc: '由服务端生成的客户端程序，运行在目标主机，通过加密 TCP 帧通道或 HTTPS 轮询通道回连服务端执行任务。',
  },
]

const modules = [
  '仪表盘：会话统计、系统信息、版本信息、通道健康',
  '会话管理：列表、信息查看、备注、心跳状态',
  '会话详情：系统信息、进程列表、进程注入、凭据、持久化',
  '交互 Shell：基于 WebSocket 的实时终端',
  '文件管理：目录浏览、上传/下载/删除/重命名/预览',
  '截图与实时屏幕流（缩放/全屏）',
  'Beacon Mesh：会话一键升级中继、多跳组网、链路状态',
  '隧道代理：SOCKS5 隧道（横向访问内网）+ 插件加载',
  'AI 副驾驶：LLM 对话 + 工具闭环 + 权限审批',
  '任务流执行：可编辑模板 + 跑完自动 AI 分析建议',
  '杀软对抗：AV 检测、EDR 失明/击杀、BYOVD、PPL 击杀',
  'BOF 插件：上传、加载与管理，DLL 句柄缓存加速',
  '运行时设置：监听器/拟态/通知/账户 热更新',
  '多平台载荷生成（exe / dll / raw / shellcode）',
  '登录日志：后台登录成功/失败审计',
]

const platforms = [
  { os: 'Windows', arch: 'amd64 / 386 / arm64', format: 'exe / dll / bin / raw / shellcode' },
  { os: 'Linux', arch: 'amd64 / 386 / arm64', format: 'elf / raw / shellcode' },
  { os: 'macOS', arch: 'amd64 / arm64', format: 'macho / raw / shellcode' },
]

const securityItems = [
  {
    icon: <FileText size={20} />,
    title: '编译期字符串混淆',
    desc: '编译前自动扫描植入端源码，将回连地址、API 函数名、配置标识、安全软件特征等敏感字符串加密为运行时解码调用。',
  },
  {
    icon: <KeyRound size={20} />,
    title: '配置块加密',
    desc: '回连地址与加密密钥以 XOR 加密块附加在二进制尾部，通过加密标识常量定位，无明文 magic 与明文 URL。',
  },
  {
    icon: <Bug size={20} />,
    title: '反沙箱 / 反调试',
    desc: '启动时检测调试器与常见沙箱/分析环境进程（VMware、VirtualBox、Sandboxie、Wireshark 等），资源不足时延迟执行。',
  },
  {
    icon: <Terminal size={20} />,
    title: '免杀工具链',
    desc: '每构建随机化配置块魔数/密钥、xd 字符串密钥基准、API 哈希种子/乘子，打破跨样本同指纹；编译期字符串混淆 + -s -w/trimpath/buildid 清理静态指纹 + 可选 garble 源码混淆；apihash/PEB 动态解析 API，进程注入随机挑选良性宿主。',
  },
]

const techStack = [
  'Go',
  'React',
  'TypeScript',
  'Vite',
  'WebSocket',
  'SQLite',
  'AES-256-GCM',
  'REST API',
]

export function About() {
  return (
    <div className="about-page">
      <div className="about-hero">
        <div className="about-logo">
          <Shell size={56} />
          <h1>ToShell</h1>
          <p className="about-version">v1.2.1</p>
        </div>
        <h2>自托管的 C2（命令与控制）远程管理平台</h2>
        <p className="about-slogan">
          ToShell（Tanovo）是一个自托管的 C2 框架，用于授权红队演练、渗透测试与安全研究。
          提供多平台、多协议的会话控制、载荷构建与隧道转发能力，覆盖从载荷生成、会话管理到
          任务执行的完整链路。请仅在获得授权的前提下使用。
        </p>
        <div className="about-authors">
          <span className="about-author-tag">作者：青山 · 核心开发者</span>
          <span className="about-author-tag">Q1lintu · 核心开发者</span>
          <span className="about-author-tag">c0ffee · 核心开发者</span>
        </div>
        <div className="about-hero-links">
          <a href="" className="about-hero-link">
            <Github size={18} /> GitHub
          </a>
          <a href="" className="about-hero-link">
            <Globe size={18} /> 官方文档
          </a>
        </div>
      </div>

      <div className="about-section">
        <h3>架构组成</h3>
        <div className="about-arch">
          {architecture.map((a) => (
            <div key={a.title} className="about-arch-card">
              <div className="about-feature-icon">{a.icon}</div>
              <h4>{a.title}</h4>
              <p>{a.desc}</p>
            </div>
          ))}
        </div>
        <p className="about-note">
          通信链路：植入端通过 <b>TCP 长连接（自定义加密帧）</b> 或 <b>HTTPS 轮询（域前置）</b> 与监听器通信
          （控制帧 AES-256-GCM + 隧道 SM4-GCM 加密）；Web 控制台通过 <b>REST API（JWT 认证）</b> 管理服务端，
          交互终端走 WebSocket 实时通道。
        </p>
      </div>

      <div className="about-section">
        <h3>核心特性</h3>
        <div className="about-features">
          {features.map((f) => (
            <div key={f.title} className="about-feature-card">
              <div className="about-feature-icon">{f.icon}</div>
              <h4>{f.title}</h4>
              <p>{f.desc}</p>
            </div>
          ))}
        </div>
      </div>

      <div className="about-section">
        <h3>主要功能</h3>
        <ul className="about-modules">
          {modules.map((m) => (
            <li key={m}>
              <span className="about-module-dot" /> {m}
            </li>
          ))}
        </ul>
      </div>

      <div className="about-section">
        <h3>支持平台与载荷格式</h3>
        <table className="about-table">
          <thead>
            <tr>
              <th>目标系统</th>
              <th>架构</th>
              <th>生成格式</th>
            </tr>
          </thead>
          <tbody>
            {platforms.map((p) => (
              <tr key={p.os}>
                <td>{p.os}</td>
                <td>{p.arch}</td>
                <td>{p.format}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="about-section">
        <h3>内置安全特性</h3>
        <div className="about-features">
          {securityItems.map((s) => (
            <div key={s.title} className="about-feature-card">
              <div className="about-feature-icon">{s.icon}</div>
              <h4>{s.title}</h4>
              <p>{s.desc}</p>
            </div>
          ))}
        </div>
        <p className="about-note about-note-warn">
          <AlertTriangle size={16} style={{ verticalAlign: '-3px' }} /> 混淆不改变载荷功能，
          但极个别杀软仍可能因行为特征报毒，建议结合 garble + UPX 使用；使用本工具请务必遵守授权范围与当地法律法规。
        </p>
      </div>

      <div className="about-section">
        <h3>技术栈</h3>
        <div className="about-tech">
          {techStack.map((t) => (
            <span key={t} className="about-tech-tag">{t}</span>
          ))}
        </div>
      </div>

      <div className="about-footer">
        <p>© 2026 ToShell (Tanovo) · 作者：青山 / Q1lintu / c0ffee（核心开发者） · 仅供授权测试与学习使用</p>
      </div>
    </div>
  )
}
