module toshell-implant

go 1.20

require (
	github.com/creack/pty v1.1.18 // !windows
	github.com/eclipse/paho.mqtt.golang v1.4.3 // transport_mqtt
	github.com/gorilla/websocket v1.5.0 // transport_ws
	github.com/refraction-networking/utls v1.4.0 // transport_http
	golang.org/x/net v0.14.0 // transport_mqtt (paho)
	golang.org/x/sync v0.4.0 // transport_mqtt (paho)
	golang.org/x/sys v0.14.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/gaukas/godicttls v0.0.3 // indirect
	github.com/klauspost/compress v1.16.6 // indirect
	github.com/quic-go/quic-go v0.37.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/text v0.14.0 // indirect
)

// 依赖版本锁定说明：
//   - x/sys/x/text/x/crypto/x/net/x/sync 固定 v0.14.x 系列（go1.20 兼容）
//   - utls v1.4.0（仅 transport_http full 档编译）
//   - creack/pty v1.1.18（仅 !windows，Linux/macOS PTY shell）
//   - gorilla/websocket v1.5.0（仅 transport_ws）
//   - paho.mqtt.golang v1.4.3（仅 transport_mqtt）
// 这些版本由本 go.mod 锁定，builder 只执行 go mod download，不做 init/get/tidy，
// 保证任何构建组合都不会把依赖升级到需要更高 Go 工具链的版本。
