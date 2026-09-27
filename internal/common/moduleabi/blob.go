package moduleabi

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// TypeModuleData 是模块二进制下行帧的协议类型号（internal/common/protocol.TypeModuleData）。
//
// 为什么把这几个字节放在 moduleabi 而 protocol 里也有一份：protocol 是**线协议**的
// 唯一定义处（服务端与植入端都要用），而本包是 **ABI** 的定义处。这里只定义"帧负载怎么排布"
// （[4B 头长][头 JSON][裸字节]），类型号仍然只在 protocol 里定义 —— 避免两处各写一个
// 数字而漂移。植入端是独立 module，用的是它自己镜像的常量（xload_windows.go）。
const blobHeaderMaxLen = 64 * 1024

// EncodeBlobFrame 把模块二进制打包成下行帧负载。
//
// 布局：[4 字节大端 header 长度][header JSON][模块裸字节]
//
// 为什么不用 base64 包一层：那正是本次要取代的做法。多 33% 的传输量之外，
// base64 会让"这一帧里到底是什么"变得只能靠解码才知道，审计日志/抓包里
// 看不出长度与哈希是否对得上。裸字节 + 明文头（头里就带 sha256/size）让
// "下发的字节"与"批准的字节"可以逐字节对照。
func EncodeBlobFrame(h *ArgumentHeader, blob []byte) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("module blob header is nil")
	}
	if len(blob) == 0 {
		return nil, fmt.Errorf("module blob is empty")
	}
	if len(blob) > MaxModuleSize {
		return nil, fmt.Errorf("module blob too large: %d > %d", len(blob), MaxModuleSize)
	}
	// 头里不放 args（args 走任务数据）：二进制帧只承载"这份字节是什么"。
	header := struct {
		ModuleID string `json:"module_id"`
		Token    string `json:"token"`
		SHA256   string `json:"sha256"`
		Size     int    `json:"size"`
		ABI      uint32 `json:"abi"`
	}{h.ModuleID, h.Token, h.SHA256, h.Size, h.ABI}

	hb, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	if len(hb) > blobHeaderMaxLen {
		return nil, fmt.Errorf("module blob header too large: %d", len(hb))
	}
	out := make([]byte, 4+len(hb)+len(blob))
	binary.BigEndian.PutUint32(out[:4], uint32(len(hb)))
	copy(out[4:], hb)
	copy(out[4+len(hb):], blob)
	return out, nil
}

// DecodeBlobFrame 解析下行帧负载（植入端与单测共用同一份口径）。
func DecodeBlobFrame(payload []byte) (*ArgumentHeader, []byte, error) {
	if len(payload) < 4 {
		return nil, nil, fmt.Errorf("module frame too short: %d bytes", len(payload))
	}
	hlen := int(binary.BigEndian.Uint32(payload[:4]))
	if hlen <= 0 || hlen > blobHeaderMaxLen || 4+hlen > len(payload) {
		return nil, nil, fmt.Errorf("module frame header length invalid: %d (payload %d)", hlen, len(payload))
	}
	var h ArgumentHeader
	if err := json.Unmarshal(payload[4:4+hlen], &h); err != nil {
		return nil, nil, fmt.Errorf("module frame header not JSON: %w", err)
	}
	blob := payload[4+hlen:]
	if len(blob) != h.Size {
		return nil, nil, fmt.Errorf("module frame size mismatch: header says %d, frame carries %d", h.Size, len(blob))
	}
	return &h, blob, nil
}
