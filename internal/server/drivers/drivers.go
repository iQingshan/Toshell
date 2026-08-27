// Package drivers 内置"已签名但易受攻击"的 BYOVD 利用驱动（原厂二进制）：
//
//	RTCore64.sys   — MICRO-STAR INTERNATIONAL（MSI Afterburner，CVE-2019-16098）：
//	                  任意物理内存读写（IOCTL 0x9C402000/0x9C402004），
//	                  PPL 击杀"物理扫描"路线依赖它。
//
// 驱动二进制来自公开渠道（GitHub 流传副本），SHA-256 已与公开报道值核对
// （RTCore64: 01AA278B…E87F1FD），Authenticode 签名验证有效（MSI 原厂证书）。
// dbutil_2_3.sys 因被微软易受攻击驱动黑名单与几乎所有杀软重点标记，不再内置；
// 如确需"虚拟地址写"备用路线，请操作员自行准备并手动上传。
// ⚠️ 仅供授权红队/渗透测试使用；加载后请及时 byovd_unload 卸载。
package drivers

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
)

//go:embed RTCore64.sys
var FS embed.FS

// Driver 描述一个内置驱动。
type Driver struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Device      string `json:"device"`  // 加载后设备路径（ppl_kill 自动检测该设备）
	Service     string `json:"service"` // 建议的 SCM 服务名
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
}

// Catalog 内置驱动目录。
var Catalog = []Driver{
	{
		Name:        "RTCore64.sys",
		Description: "MSI Afterburner 驱动（CVE-2019-16098）：任意物理内存读写，PPL 击杀物理扫描路线",
		Device:      `\\.\RTCore64`,
		Service:     "RTCore64",
	},
}

// List 返回驱动目录（附带实时大小与 SHA-256）。
func List() []Driver {
	out := make([]Driver, len(Catalog))
	copy(out, Catalog)
	for i := range out {
		if data, err := FS.ReadFile(out[i].Name); err == nil {
			out[i].Size = int64(len(data))
			h := sha256.Sum256(data)
			out[i].SHA256 = hex.EncodeToString(h[:])
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}

// Get 返回指定名称驱动的信息与原始字节。
func Get(name string) (Driver, []byte, error) {
	for _, d := range Catalog {
		if d.Name == name {
			data, err := FS.ReadFile(name)
			if err != nil {
				return d, nil, err
			}
			return d, data, nil
		}
	}
	return Driver{}, nil, fmt.Errorf("unknown driver: %s", name)
}
