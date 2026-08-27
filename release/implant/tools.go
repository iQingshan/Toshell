//go:build tools

package main

// 构建标签相关依赖的显式声明：这些包只在特定 -tags 下被源码 import，
// go mod tidy 默认（不带 tags）扫描时会忽略它们并可能把依赖升级到
// 需要更高 Go 版本的最新版（cannot compile Go 1.23 code）。
// 通过本文件的显式 import + go.mod 锁定版本，保证 go mod download
// 始终拉取 go1.20 兼容版本。本文件不参与实际编译（tools 标签）。
import (
	_ "github.com/creack/pty"
	_ "github.com/gorilla/websocket"
	_ "github.com/refraction-networking/utls"
)
