//go:build !windows || !execmodule

package main

// 内存模块按需加载的**默认实现**（未加 -tags execmodule）。
//
// 为什么默认不给真实实现、也不给"半可用"实现：
//   - 默认载荷必须与改动前逐字节行为一致（体积也基本不变）。exec_module 会引入
//     反射加载器调用面 + sha256 校验 + 模块 ABI 结构，顺手得到它不符合"想拿到
//     额外能力就显式勾选"的口径（与 bof / evasionscan 同一规矩）。
//   - 服务端侧同样有闸门：/sessions/{id}/module 会先看会话上报的能力位里有没有
//     exec_module（cap:v1 位图），没有就直接拒绝，不会推一份二进制过来白白占带宽。
//
// 所以这里给出**明确失败**而不是静默成功：任务返回中文原因 + 非 0 退出码，
// 操作员一眼能看出"这个载荷没编这个能力"，而不是"模块有问题"。

// handleXLoad 未编译 execmodule 时的空实现。
func handleXLoad(data string) (string, int32, string) {
	_ = data
	return "", -1, "exec_module 未包含在本次构建中：该载荷没有编译内存模块支持（需要 -tags execmodule 重新构建）"
}

// handleXData 未编译 execmodule 时忽略模块二进制下行帧。
// 服务端正常情况下不会推（能力位不含 exec_module 即拒绝），这里兜住"手动构造帧"的场景。
func handleXData(p *Packet) {
	_ = p
}
