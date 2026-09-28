package drivers

import (
	"encoding/json"
	"strings"
	"testing"
)

// ─── catalog 签名驱动支持：声明解析 + 声明↔实测一致性（v1.4.0 S6 P0-1）────────
//
// 分两层测：
//  1. 纯逻辑（SignatureConsistency）：喂假数据覆盖"一致/不一致/无法比较"全部分支；
//  2. manifest 解析 + 目录汇总（declaration/Summary.Signatures）：确认操作员手写的
//     各种 signed 写法都能被正确收敛，且预览里能看到"缺签名/声明未签名"。

// TestSignatureDeclarationParseAsManifest 兼容三种 signed 写法 + signer/require_signature。
func TestSignatureDeclarationParseAsManifest(t *testing.T) {
	raw := `{"drivers":[
		{"file":"a.sys","name":"a","signed":"Contoso Ltd."},
		{"file":"b.sys","name":"b","signed":true},
		{"file":"c.sys","name":"c","signed":false},
		{"file":"d.sys","name":"d"},
		{"file":"e.sys","name":"e","signer":"Fabrikam"},
		{"file":"f.sys","name":"f","signed":"false"},
		{"file":"g.sys","name":"g","signed":"","require_signature":true}
	]}`
	var m manifestFile
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("manifest 解析失败：%v", err)
	}
	byName := map[string]manifestEntry{}
	for _, e := range m.Drivers {
		byName[e.Name] = e
	}
	cases := []struct {
		name       string
		declared   string
		signer     string
		require    bool
		legacyName string // 兼容字段 Driver.Signed 里应出现的签名者
	}{
		{"a", SignatureSigned, "Contoso Ltd.", false, "Contoso Ltd."},
		{"b", SignatureSigned, "", false, ""},
		{"c", SignatureUnsigned, "", false, ""},
		{"d", SignatureUnset, "", false, ""},
		{"e", SignatureSigned, "Fabrikam", false, "Fabrikam"},
		{"f", SignatureUnsigned, "", false, ""}, // "false" 是布尔被写成字符串，不能当成签名者
		{"g", SignatureUnset, "", true, ""},
	}
	for _, c := range cases {
		d := byName[c.name].declaration()
		if d.Declared != c.declared || d.Signer != c.signer || d.Require != c.require {
			t.Errorf("%s.sys declaration = %+v, want declared=%q signer=%q require=%v",
				c.name, d, c.declared, c.signer, c.require)
		}
		// 兼容字段 Driver.Signed（前端在用）必须等于"声明的签名者"（含显式 signer 字段）
		drv := Driver{Name: c.name, File: c.name + ".sys"}
		matchManifest(c.name+".sys", &drv, m)
		if drv.Signed != c.legacyName {
			t.Errorf("%s.sys 兼容字段签名者 = %q, want %q", c.name, drv.Signed, c.legacyName)
		}
		if drv.Signature.Declared != c.declared || drv.Signature.Require != c.require {
			t.Errorf("%s.sys Driver.Signature = %+v, want declared=%q require=%v",
				c.name, drv.Signature, c.declared, c.require)
		}
		// 一致性说明必须能自解释（前端直接展示）
		if note := d.ConsistencyNote(); strings.TrimSpace(note) == "" {
			t.Errorf("%s.sys 的声明摘要不能为空", c.name)
		}
	}
}

// TestSignatureConsistencyVerdicts 声明与实测的一致性判定（含默认"只警告不拒绝"）。
func TestSignatureConsistencyVerdicts(t *testing.T) {
	unsigned := SignatureStatus{Checked: true, Signed: false}
	signedBy := func(signer string) SignatureStatus {
		return SignatureStatus{Checked: true, Signed: true, Signer: signer}
	}
	unchecked := SignatureStatus{Checked: false}

	type tc struct {
		name       string
		decl       SignatureDeclaration
		sig        SignatureStatus
		wantNil    bool // consistent 是否为 nil（无法比较）
		wantConsis bool
		wantErr    bool // Errors 非空（调用方必须拒绝）
		wantWarn   string
		wantErrSub string
	}
	cases := []tc{
		{name: "声明已签名+实测未签名(默认只警告)", decl: SignatureDeclaration{Declared: SignatureSigned},
			sig: unsigned, wantConsis: false, wantWarn: "签名声明与实测不一致"},
		{name: "声明已签名+实测未签名(require=硬拒)", decl: SignatureDeclaration{Declared: SignatureSigned, Require: true},
			sig: unsigned, wantConsis: false, wantErr: true, wantErrSub: "require_signature=true"},
		{name: "声明已签名+签名者不符(默认警告)", decl: SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso Ltd."},
			sig: signedBy("Fabrikam Inc."), wantConsis: false, wantWarn: "不一致"},
		{name: "声明已签名+签名者不符(require=硬拒)", decl: SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso", Require: true},
			sig: signedBy("Fabrikam"), wantConsis: false, wantErr: true},
		{name: "声明已签名+签名者简称匹配", decl: SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso"},
			sig: signedBy("Contoso Ltd."), wantConsis: true},
		{name: "声明已签名+实测签名有效但取不到签名者", decl: SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso"},
			sig: signedBy(""), wantConsis: true},
		{name: "声明未签名+实测签名有效", decl: SignatureDeclaration{Declared: SignatureUnsigned},
			sig: signedBy("Contoso"), wantConsis: false, wantWarn: "声明该驱动未签名"},
		{name: "声明未签名+实测未签名", decl: SignatureDeclaration{Declared: SignatureUnsigned},
			sig: unsigned, wantConsis: true},
		{name: "未声明+实测未签名(缺签名要能看出来)", decl: SignatureDeclaration{},
			sig: unsigned, wantNil: true, wantWarn: "未声明该驱动的签名信息"},
		{name: "未声明+实测已签名", decl: SignatureDeclaration{},
			sig: signedBy("Contoso"), wantNil: true},
		{name: "未声明+未跑校验", decl: SignatureDeclaration{},
			sig: unchecked, wantNil: true},
		{name: "有声明但未跑校验(无法核对)", decl: SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso"},
			sig: unchecked, wantNil: true, wantWarn: "无法核对"},
		{name: "require 但未跑校验(fail-closed 拒绝)", decl: SignatureDeclaration{Require: true},
			sig: unchecked, wantNil: true, wantErr: true, wantErrSub: "无法确认"},
		{name: "声明自相矛盾(require+未签名)", decl: SignatureDeclaration{Declared: SignatureUnsigned, Require: true},
			sig: unsigned, wantNil: true, wantErr: true, wantErrSub: "自相矛盾"},
		{name: "require+实测未签名(未声明档位)", decl: SignatureDeclaration{Require: true},
			sig: unsigned, wantConsis: false, wantErr: true, wantWarn: "未声明该驱动的签名信息"},
		{name: "require+实测已签名", decl: SignatureDeclaration{Require: true},
			sig: signedBy("Contoso"), wantConsis: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			consistent, warns, errs := SignatureConsistency(c.decl, c.sig)
			if c.wantNil {
				if consistent != nil {
					t.Fatalf("consistent 应为 nil（无法比较），实际 %v", *consistent)
				}
			} else {
				if consistent == nil {
					t.Fatalf("consistent 不应为 nil")
				}
				if *consistent != c.wantConsis {
					t.Fatalf("consistent = %v, want %v", *consistent, c.wantConsis)
				}
			}
			if c.wantErr && len(errs) == 0 {
				t.Fatalf("应产生 Errors（调用方据此拒绝），实际 warnings=%v", warns)
			}
			if !c.wantErr && len(errs) != 0 {
				t.Fatalf("默认口径只应警告、不应报错，实际 errors=%v", errs)
			}
			if c.wantWarn != "" {
				joined := strings.Join(append(append([]string{}, warns...), errs...), "｜")
				if !strings.Contains(joined, c.wantWarn) {
					t.Fatalf("缺少警告 %q，实际 warns=%v errs=%v", c.wantWarn, warns, errs)
				}
			}
			if c.wantErrSub != "" && !strings.Contains(strings.Join(errs, "｜"), c.wantErrSub) {
				t.Fatalf("错误信息缺少 %q：%v", c.wantErrSub, errs)
			}
		})
	}
}

// TestBuildVerifyResultCarriesDeclarationSignature 合并结论里必须带上声明字段与一致性结论，
// 否则前端只能看到"未签名"，看不出"声明与实测不符"。
func TestBuildVerifyResultCarriesDeclarationSignature(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	decl := SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso Ltd.", Require: false}
	res := buildVerifyResult(sum, sum, decl, SignatureStatus{Checked: true, Signed: false}, BlocklistStatus{})
	if res.DeclaredSignature != SignatureSigned || res.DeclaredSigner != "Contoso Ltd." || res.RequireSignature {
		t.Fatalf("声明字段未回填：%+v", res)
	}
	if res.SignatureConsistent == nil || *res.SignatureConsistent {
		t.Fatalf("声明已签名而实测未签名 → SignatureConsistent 应为 false，实际 %v", res.SignatureConsistent)
	}
	joined := strings.Join(res.Warnings, "｜")
	if !strings.Contains(joined, "签名声明与实测不一致") {
		t.Fatalf("warnings 应含不一致说明：%v", res.Warnings)
	}
	// 默认不因"声明与实测不一致"拒绝下发（Errors 只来自哈希/require/平台错误）
	if len(res.Errors) != 0 {
		t.Fatalf("默认口径不应产生 Errors，实际 %v", res.Errors)
	}

	// require_signature=true 时同一份输入必须变成硬拒
	res2 := buildVerifyResult(sum, sum, SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso", Require: true},
		SignatureStatus{Checked: true, Signed: false}, BlocklistStatus{})
	if len(res2.Errors) == 0 {
		t.Fatal("require_signature=true 时必须产生 Errors（硬拒）")
	}
}

// TestSummaryReportsSignatureDeclarations 目录汇总要能体现"缺签名/声明未签名"，
// 并按档位给出会挑中哪个驱动（含它的签名声明）。
func TestSummaryReportsSignatureDeclarations(t *testing.T) {
	writeDriverDir(t, `{"drivers":[
		{"file":"killer.sys","name":"killer","purpose":"kill","device":"\\\\.\\killer","ioctl":"0x222048","signed":"Contoso Ltd.","sha256":"x"},
		{"file":"rwdrv.sys","name":"rwdrv","purpose":"rw","signed":false},
		{"file":"nosign.sys","name":"nosign","purpose":"kill","device":"\\\\.\\nosign","ioctl":"0x222049"}
	]}`, "killer.sys", "rwdrv.sys", "nosign.sys")

	sum := Summary()
	if sum.Signatures.DeclaredSigned != 1 || sum.Signatures.DeclaredUnsigned != 1 || sum.Signatures.Undeclared != 1 {
		t.Fatalf("签名声明统计 = %+v, want 1/1/1", sum.Signatures)
	}
	if !strings.Contains(sum.Signatures.Note, "不做 Authenticode 校验") {
		t.Errorf("汇总必须说明这是声明而非实测：%q", sum.Signatures.Note)
	}
	// kill 档：killer 声明已签名 → 被选中并带上声明
	if sum.Kill == nil || sum.Kill.Name != "killer" {
		t.Fatalf("Kill = %+v, want killer（专用 kill 档优先于 both/其它）", sum.Kill)
	}
	if sum.Kill.Signature.Declared != SignatureSigned || sum.Kill.Signature.Signer != "Contoso Ltd." {
		t.Fatalf("选中档案应带签名声明：%+v", sum.Kill.Signature)
	}
	// rw 档：显式声明未签名，预览应能看出来（前端据此标黄）
	if sum.RW == nil || sum.RW.Signature.Declared != SignatureUnsigned {
		t.Fatalf("RW 应带「声明未签名」：%+v", sum.RW)
	}
}

// TestNonWindowsDeclarationIsReportedNotEnforced 非 Windows 平台（CI 的 Linux runner）：
// 签名声明必须**原样回显**并明确写出"未被核对、未被强制执行"，而不是静默当成"已签名"。
// Windows 上这个用例没有意义（那里会真的验签），因此显式跳过。
func TestNonWindowsDeclarationIsReportedNotEnforced(t *testing.T) {
	if SelfCheckSupported() {
		t.Skip("Windows 平台会真的执行 Authenticode 校验，本用例只覆盖「校验不可用」的占位分支")
	}
	decl := SignatureDeclaration{Declared: SignatureSigned, Signer: "Contoso Ltd.", Require: true}
	res := verifyWithRawDecl("drivers/demo.sys", []byte("x"), "", decl)
	if res.DeclaredSignature != SignatureSigned || res.DeclaredSigner != "Contoso Ltd." || !res.RequireSignature {
		t.Fatalf("非 Windows 占位结论必须回显签名声明：%+v", res)
	}
	joined := strings.Join(res.Warnings, "｜")
	for _, want := range []string{"非 Windows", "未被强制执行", "require_signature"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("占位结论缺少 %q：%v", want, res.Warnings)
		}
	}
	if res.SignatureConsistent != nil {
		t.Fatal("没有实测结论时不应给出「一致/不一致」")
	}
}

// TestManifestDeclarationLookup 按文件名/驱动名查签名声明（上传字节的自检走这条路径）。
func TestManifestDeclarationLookup(t *testing.T) {
	writeDriverDir(t, `{"drivers":[{"file":"demo.sys","name":"demo","purpose":"kill","signed":"Contoso Ltd.","sha256":"abc"}]}`, "demo.sys")

	sha, decl := manifestDeclarationFor("drivers/demo.sys")
	if sha != "abc" || decl.Signer != "Contoso Ltd." || decl.Declared != SignatureSigned {
		t.Fatalf("按文件名查声明失败：sha=%q decl=%+v", sha, decl)
	}
	// 兼容入口（二元返回）仍然给出签名者
	_, signer := manifestExpectedFor("drivers/demo.sys")
	if signer != "Contoso Ltd." {
		t.Fatalf("兼容入口签名者 = %q", signer)
	}
	// 同名驱动的声明也能按档案名查到（byovd_load 上传时用 name）
	_, decl2 := manifestDeclarationIn("drivers", "demo")
	if decl2.Declared != SignatureSigned {
		t.Fatalf("按驱动名查声明失败：%+v", decl2)
	}
}
