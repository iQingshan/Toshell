//go:build !transport_http && !transport_ws && !transport_mqtt

package main

// HTTP(S) 轮询通道 stub（transport=tcp/websocket 的紧凑构建）。
// 未启用 HTTP 通道时不引入 net/http / crypto/tls，显著减小植入端体积。
// main.go 的通道选择逻辑在 transportMode=tcp 时不会调用本文件函数。

func isHTTPTransport(s string) bool { return false }

// isWSTransport 判断 serverAddr 是否为 WebSocket 通道（非 transport_ws 构建恒 false）。
func isWSTransport(s string) bool { return false }

// isMQTTTransport 判断 serverAddr 是否为 MQTT 通道（非 transport_mqtt 构建恒 false）。
func isMQTTTransport(s string) bool { return false }

func httpPollRun() {}

func httpSendFrame(p *Packet) bool { return false }

// wsPollRun stub：非 transport_ws 构建不含 WebSocket 通道（main.go 的通道选择
// 在 transportMode=websocket 时恒不进入，此处仅为满足编译引用）。
func wsPollRun() {}

// mqttPollRun stub：非 transport_mqtt 构建不含 MQTT 通道。
func mqttPollRun() {}

var httpMode bool // 恒为 false：TCP 通道下 sendPacketSync 走原生 socket
