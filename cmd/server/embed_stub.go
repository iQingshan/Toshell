//go:build !webui

package main

import "embed"

// 默认构建不嵌入前端（webdist 不可用）。
// 需要内嵌前端时使用: go build -tags webui ./cmd/server
var webDistFS embed.FS
