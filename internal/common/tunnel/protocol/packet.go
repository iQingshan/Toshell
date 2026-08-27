package protocol

import (
	"encoding/binary"
	"time"
)

type Packet struct {
	Magic    [2]byte
	Version  byte
	Type     byte
	Flags    byte
	TunnelID uint32
	Length   uint32
	Sequence uint32
	Payload  []byte
}

type TunnelInfo struct {
	ID         uint32            `json:"id"`
	Protocol   string            `json:"protocol"`
	TargetAddr string            `json:"target_addr"`
	TargetPort uint16            `json:"target_port"`
	SourceAddr string            `json:"source_addr"`
	SourcePort uint16            `json:"source_port"`
	CreatedAt  int64             `json:"created_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type HeartbeatPayload struct {
	Timestamp     int64   `json:"timestamp"`
	ActiveTunnels int     `json:"active_tunnels"`
	BytesIn       uint64  `json:"bytes_in"`
	BytesOut      uint64  `json:"bytes_out"`
	CPUUsage      float32 `json:"cpu_usage"`
	MemoryUsed    uint64  `json:"memory_used"`
}

type TunnelAckPayload struct {
	TunnelID uint32 `json:"tunnel_id"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type DataBatchPayload struct {
	Count    int      `json:"count"`
	TunnelID uint32   `json:"tunnel_id"`
	Lengths  []uint32 `json:"lengths"`
	Data     []byte   `json:"data"`
}

func NewPacket(pktType byte, tunnelID uint32, payload []byte) *Packet {
	return &Packet{
		Magic:    [2]byte{MagicByte1, MagicByte2},
		Version:  ProtocolVersion,
		Type:     pktType,
		Flags:    0,
		TunnelID: tunnelID,
		Length:   uint32(len(payload)),
		Sequence: 0,
		Payload:  payload,
	}
}

func NewHeartbeatPacket(tunnelID uint32, hb *HeartbeatPayload) *Packet {
	payload := hb.Marshal()
	return NewPacket(TypeHeartbeat, tunnelID, payload)
}

func NewTunnelPacket(tunnelID uint32, info *TunnelInfo) *Packet {
	payload := info.Marshal()
	return NewPacket(TypeNewTunnel, tunnelID, payload)
}

func NewDataPacket(tunnelID uint32, data []byte) *Packet {
	return NewPacket(TypeData, tunnelID, data)
}

func NewClosePacket(tunnelID uint32) *Packet {
	return NewPacket(TypeCloseTunnel, tunnelID, nil)
}

func NewAckPacket(tunnelID uint32, success bool, errMsg string) *Packet {
	ack := &TunnelAckPayload{
		TunnelID: tunnelID,
		Success:  success,
		Error:    errMsg,
	}
	return NewPacket(TypeTunnelAck, tunnelID, ack.Marshal())
}

func NewErrorPacket(code int, message string) *Packet {
	err := &ErrorPayload{
		Code:    code,
		Message: message,
	}
	return NewPacket(TypeError, 0, err.Marshal())
}

func (p *Packet) SetFlag(flag byte) {
	p.Flags |= flag
}

func (p *Packet) HasFlag(flag byte) bool {
	return p.Flags&flag != 0
}

func (p *Packet) ClearFlag(flag byte) {
	p.Flags &^= flag
}

func (hb *HeartbeatPayload) Marshal() []byte {
	data := make([]byte, 48)
	binary.BigEndian.PutUint64(data[0:8], uint64(hb.Timestamp))
	binary.BigEndian.PutUint32(data[8:12], uint32(hb.ActiveTunnels))
	binary.BigEndian.PutUint64(data[12:20], hb.BytesIn)
	binary.BigEndian.PutUint64(data[20:28], hb.BytesOut)
	binary.BigEndian.PutUint32(data[28:32], uint32(hb.CPUUsage * 1000))
	binary.BigEndian.PutUint64(data[32:40], hb.MemoryUsed)
	return data[:40]
}

func UnmarshalHeartbeat(data []byte) (*HeartbeatPayload, error) {
	if len(data) < 40 {
		return nil, ErrPacketTooShort
	}
	hb := &HeartbeatPayload{
		Timestamp:     int64(binary.BigEndian.Uint64(data[0:8])),
		ActiveTunnels: int(binary.BigEndian.Uint32(data[8:12])),
		BytesIn:       binary.BigEndian.Uint64(data[12:20]),
		BytesOut:      binary.BigEndian.Uint64(data[20:28]),
		CPUUsage:      float32(binary.BigEndian.Uint32(data[28:32])) / 1000,
		MemoryUsed:    binary.BigEndian.Uint64(data[32:40]),
	}
	return hb, nil
}

func (ti *TunnelInfo) Marshal() []byte {
	addrBytes := []byte(ti.TargetAddr)
	srcAddrBytes := []byte(ti.SourceAddr)
	
	totalLen := 4 + 1 + len(addrBytes) + 2 + len(srcAddrBytes) + 2 + 8 + 4
	if ti.Metadata != nil {
		for k, v := range ti.Metadata {
			totalLen += 2 + len(k) + 2 + len(v)
		}
	}
	
	data := make([]byte, totalLen)
	offset := 0
	
	binary.BigEndian.PutUint32(data[offset:], ti.ID)
	offset += 4
	
	data[offset] = protocolToByte(ti.Protocol)
	offset += 1
	
	binary.BigEndian.PutUint16(data[offset:], uint16(len(addrBytes)))
	offset += 2
	copy(data[offset:], addrBytes)
	offset += len(addrBytes)
	
	binary.BigEndian.PutUint16(data[offset:], ti.TargetPort)
	offset += 2
	
	binary.BigEndian.PutUint16(data[offset:], uint16(len(srcAddrBytes)))
	offset += 2
	copy(data[offset:], srcAddrBytes)
	offset += len(srcAddrBytes)
	
	binary.BigEndian.PutUint16(data[offset:], ti.SourcePort)
	offset += 2
	
	binary.BigEndian.PutUint64(data[offset:], uint64(ti.CreatedAt))
	offset += 8
	
	if ti.Metadata != nil {
		binary.BigEndian.PutUint32(data[offset:], uint32(len(ti.Metadata)))
		offset += 4
		
		for k, v := range ti.Metadata {
			binary.BigEndian.PutUint16(data[offset:], uint16(len(k)))
			offset += 2
			copy(data[offset:], k)
			offset += len(k)
			
			binary.BigEndian.PutUint16(data[offset:], uint16(len(v)))
			offset += 2
			copy(data[offset:], v)
			offset += len(v)
		}
	} else {
		binary.BigEndian.PutUint32(data[offset:], 0)
		offset += 4
	}
	
	return data[:offset]
}

func UnmarshalTunnelInfo(data []byte) (*TunnelInfo, error) {
	if len(data) < 23 {
		return nil, ErrPacketTooShort
	}
	
	ti := &TunnelInfo{}
	offset := 0
	
	ti.ID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	ti.Protocol = byteToProtocol(data[offset])
	offset += 1
	
	addrLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+addrLen {
		return nil, ErrPacketTooShort
	}
	ti.TargetAddr = string(data[offset : offset+addrLen])
	offset += addrLen
	
	ti.TargetPort = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	
	srcAddrLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	if len(data) < offset+srcAddrLen {
		return nil, ErrPacketTooShort
	}
	ti.SourceAddr = string(data[offset : offset+srcAddrLen])
	offset += srcAddrLen
	
	ti.SourcePort = binary.BigEndian.Uint16(data[offset:])
	offset += 2
	
	ti.CreatedAt = int64(binary.BigEndian.Uint64(data[offset:]))
	offset += 8
	
	if len(data) >= offset+4 {
		metaCount := int(binary.BigEndian.Uint32(data[offset:]))
		offset += 4
		
		if metaCount > 0 {
			ti.Metadata = make(map[string]string)
			for i := 0; i < metaCount; i++ {
				if len(data) < offset+2 {
					break
				}
				keyLen := int(binary.BigEndian.Uint16(data[offset:]))
				offset += 2
				if len(data) < offset+keyLen {
					break
				}
				key := string(data[offset : offset+keyLen])
				offset += keyLen
				
				if len(data) < offset+2 {
					break
				}
				valLen := int(binary.BigEndian.Uint16(data[offset:]))
				offset += 2
				if len(data) < offset+valLen {
					break
				}
				val := string(data[offset : offset+valLen])
				offset += valLen
				
				ti.Metadata[key] = val
			}
		}
	}
	
	return ti, nil
}

func (ack *TunnelAckPayload) Marshal() []byte {
	errBytes := []byte(ack.Error)
	data := make([]byte, 4+1+2+len(errBytes))
	offset := 0
	
	binary.BigEndian.PutUint32(data[offset:], ack.TunnelID)
	offset += 4
	
	if ack.Success {
		data[offset] = 1
	} else {
		data[offset] = 0
	}
	offset += 1
	
	binary.BigEndian.PutUint16(data[offset:], uint16(len(errBytes)))
	offset += 2
	copy(data[offset:], errBytes)
	
	return data
}

func UnmarshalTunnelAck(data []byte) (*TunnelAckPayload, error) {
	if len(data) < 7 {
		return nil, ErrPacketTooShort
	}
	
	ack := &TunnelAckPayload{}
	offset := 0
	
	ack.TunnelID = binary.BigEndian.Uint32(data[offset:])
	offset += 4
	
	ack.Success = data[offset] == 1
	offset += 1
	
	errLen := int(binary.BigEndian.Uint16(data[offset:]))
	offset += 2
	
	if len(data) >= offset+errLen {
		ack.Error = string(data[offset : offset+errLen])
	}
	
	return ack, nil
}

func (err *ErrorPayload) Marshal() []byte {
	msgBytes := []byte(err.Message)
	data := make([]byte, 4+2+len(msgBytes))
	
	binary.BigEndian.PutUint32(data[0:4], uint32(err.Code))
	binary.BigEndian.PutUint16(data[4:6], uint16(len(msgBytes)))
	copy(data[6:], msgBytes)
	
	return data
}

func UnmarshalError(data []byte) (*ErrorPayload, error) {
	if len(data) < 6 {
		return nil, ErrPacketTooShort
	}
	
	err := &ErrorPayload{
		Code: int(binary.BigEndian.Uint32(data[0:4])),
	}
	
	msgLen := int(binary.BigEndian.Uint16(data[4:6]))
	if len(data) >= 6+msgLen {
		err.Message = string(data[6 : 6+msgLen])
	}
	
	return err, nil
}

func protocolToByte(p string) byte {
	switch p {
	case ProtocolTCP:
		return 0x01
	case ProtocolUDP:
		return 0x02
	case ProtocolSOCKS5:
		return 0x03
	case ProtocolHTTP:
		return 0x04
	default:
		return 0x01
	}
}

func byteToProtocol(b byte) string {
	switch b {
	case 0x01:
		return ProtocolTCP
	case 0x02:
		return ProtocolUDP
	case 0x03:
		return ProtocolSOCKS5
	case 0x04:
		return ProtocolHTTP
	default:
		return ProtocolTCP
	}
}

func NewTunnelInfo(id uint32, protocol, targetAddr string, targetPort uint16) *TunnelInfo {
	return &TunnelInfo{
		ID:         id,
		Protocol:   protocol,
		TargetAddr: targetAddr,
		TargetPort: targetPort,
		CreatedAt:  time.Now().UnixMilli(),
		Metadata:   make(map[string]string),
	}
}
