package protocol

const (
	MagicByte1      = 0x7F
	MagicByte2      = 0x54
	ProtocolVersion = 0x02
	HeaderSize      = 16
	MaxPayloadSize  = 10 * 1024 * 1024
)

const (
	TypeHandshake   = 0x00
	TypeHeartbeat   = 0x01
	TypeNewTunnel   = 0x02
	TypeCloseTunnel = 0x03
	TypeTunnelAck   = 0x04
	TypeTunnelSync  = 0x05
	TypeTunnelList  = 0x06
	TypeError       = 0x0F

	TypeData      = 0x10
	TypeDataAck   = 0x11
	TypeDataBatch = 0x12
)

const (
	FlagCompressed = 0x01 // gzip 压缩（已废弃，推荐 FlagSnappy）
	FlagEncrypted  = 0x02
	FlagPriority   = 0x04
	FlagFinal      = 0x08
	FlagBatch      = 0x10
	FlagSnappy     = 0x20 // Snappy 压缩（比 gzip 快 10 倍）
)

const (
	ProtocolTCP    = "tcp"
	ProtocolUDP    = "udp"
	ProtocolSOCKS5 = "socks5"
	ProtocolHTTP   = "http"
)

type ConnState int

const (
	ConnStateActive ConnState = iota
	ConnStateIdle
	ConnStateClosed
)

type TunnelState int

const (
	TunnelStatePending TunnelState = iota
	TunnelStateActive
	TunnelStateClosed
	TunnelStateError
)
