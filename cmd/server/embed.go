//go:build webui

package main

import "embed"

//go:embed webdist
var webDistFS embed.FS
