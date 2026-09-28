// catalog / manifest 的「签名信息」声明与「声明 ↔ 实测」一致性判定（v1.4.0 S6 P0-1 补完）。
//
// 为什么要把"声明"与"实测"分成两层：
//   - 实测结论（WinVerifyTrust/Authenticode）**依赖本机**：非 Windows 控制端根本没有
//     WinVerifyTrust，Windows 上证书链/吊销检查超时（SignatureTimeout=4s）时我们故意不缓存
//     结论，同一份驱动下一次可能给出不同答案。让"这个驱动必须是已签名的"这件事只能靠实测，
//     等于在 Linux 托管的控制端上完全无法表达；
//   - 声明又是人工写的，可能过期或写错，只有声明同样不行。
//
// 因此：SignatureDeclaration = manifest 里的人工声明；SignatureStatus/VerifyResult = 本机实测；
// SignatureConsistency 负责给出"一致 / 不一致 / 无法比较"的判定，三个调用点（List、
// GET /drivers/{name}/verify、byovd_load 的加载前自检）共用同一份口径。
package drivers

import (
	"encoding/json"
	"fmt"
	"strings"
)

// 签名声明三态（SignatureDeclaration.Declared 的取值）。
const (
	// SignatureUnset 未声明：既没说已签名，也没说未签名。
	SignatureUnset = ""
	// SignatureSigned manifest 声明该驱动已签名（可选带签名者）。
	SignatureSigned = "signed"
	// SignatureUnsigned manifest 显式声明该驱动未签名（signed: false）。
	SignatureUnsigned = "unsigned"
)

// SignatureDeclaration manifest 里对签名的声明（**人工声明，不等于实测结论**）。
//
// 兼容既有写法：v1.3.4 起 manifest 的 "signed" 字段是"签名者字符串"，这里扩展为
// 布尔 / 字符串两用，并新增可选的 "signer"（显式签名者）与 "require_signature"
// （把签名要求变成硬闸门）。
type SignatureDeclaration struct {
	// Declared 三态：""（未声明）/ "signed" / "unsigned"。
	Declared string `json:"declared,omitempty"`
	// Signer 声明的签名者（人工填写，常写简称；判定用包含关系，见 signerMatches）。
	Signer string `json:"signer,omitempty"`
	// Require 声明"实测必须签名有效"（manifest 的 require_signature: true）。
	// 默认 false：声明与实测不一致时**只警告不拒绝**，理由见 SignatureConsistency。
	Require bool `json:"require,omitempty"`
}

// Empty 判断声明是否什么都没写（用于"要不要提示补全"）。
func (d SignatureDeclaration) Empty() bool {
	return d.Declared == SignatureUnset && strings.TrimSpace(d.Signer) == "" && !d.Require
}

// ConsistencyNote 给接口/前端用的一句话声明摘要（没有实测结论）。
func (d SignatureDeclaration) ConsistencyNote() string {
	switch d.Declared {
	case SignatureSigned:
		if strings.TrimSpace(d.Signer) != "" {
			return "manifest 声明：已签名（签名者 " + strings.TrimSpace(d.Signer) + "）"
		}
		return "manifest 声明：已签名（未写签名者）"
	case SignatureUnsigned:
		return "manifest 声明：未签名"
	default:
		if d.Require {
			return "manifest 未声明签名信息，但要求实测签名有效（require_signature=true）"
		}
		return "manifest 未声明签名信息"
	}
}

// signedDecl manifest 里 signed 字段的解析结果（signed 可以是字符串或布尔）。
//
// 为什么用自定义类型而不是 json.RawMessage：manifest 是操作员手写的，写法五花八门，
// 解析层必须一次把三种写法（"Contoso Ltd." / true / false）收敛成同一份内部表示，
// 否则每个调用点都要各自判类型 —— 那正是"同一个字段在不同路径上解释不同"的来源。
type signedDecl struct {
	Declared string
	Signer   string
}

// UnmarshalJSON 兼容 signed 的三种写法：
//
//	"signed": "Contoso Ltd."  → 声明已签名，签名者 Contoso Ltd.（v1.3.4 起的既有写法）
//	"signed": true            → 声明已签名（签名者未知）
//	"signed": false           → 声明未签名
//	"signed": "true"/"false"  → 按布尔处理（有人会把布尔写成字符串）
//	""/null                   → 未声明
func (s *signedDecl) UnmarshalJSON(b []byte) error {
	raw := strings.TrimSpace(string(b))
	if raw == "" || raw == "null" {
		*s = signedDecl{}
		return nil
	}
	switch raw[0] {
	case 't', 'T', 'f', 'F':
		var v bool
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf(`signed 必须是布尔或字符串（字符串表示签名者）：%v`, err)
		}
		if v {
			s.Declared = SignatureSigned
		} else {
			s.Declared = SignatureUnsigned
		}
		return nil
	}
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return fmt.Errorf(`signed 必须是布尔或字符串（字符串表示签名者）：%v`, err)
	}
	v = strings.TrimSpace(v)
	if v == "" {
		*s = signedDecl{}
		return nil
	}
	// "true"/"false" 这种"布尔被写成字符串"的写法按布尔解释，避免把 "false" 当成签名者名字。
	switch strings.ToLower(v) {
	case "true":
		s.Declared = SignatureSigned
		return nil
	case "false":
		s.Declared = SignatureUnsigned
		return nil
	}
	s.Declared = SignatureSigned
	s.Signer = v
	return nil
}

// declaration 把 manifest 条目里的签名声明收敛成 SignatureDeclaration。
// signer 字段（显式签名者）优先于 signed 里的字符串。
func (m manifestEntry) declaration() SignatureDeclaration {
	d := SignatureDeclaration{
		Declared: m.Signed.Declared,
		Signer:   strings.TrimSpace(m.Signed.Signer),
		Require:  m.RequireSignature,
	}
	if extra := strings.TrimSpace(m.Signer); extra != "" {
		d.Signer = extra
	}
	// 只写了 signer、没写 signed：视为"声明已签名 + 该签名者"（与 v1.3.4 的语义一致）。
	if d.Declared == SignatureUnset && d.Signer != "" {
		d.Declared = SignatureSigned
	}
	return d
}

// declarationFromSigner 把 v1.3.4 的"单独一个签名者字符串"包装成声明，
// 供 BuildVerifyResult/verifyWithRaw 这些**保持旧函数签名**的兼容入口使用。
func declarationFromSigner(signer string) SignatureDeclaration {
	s := strings.TrimSpace(signer)
	if s == "" {
		return SignatureDeclaration{}
	}
	return SignatureDeclaration{Declared: SignatureSigned, Signer: s}
}

// SignatureConsistency 纯逻辑：比对 manifest 的签名声明与本机实测的签名结论。
//
// 返回值：
//   - consistent：nil = 无法比较（没有声明，或本次根本没跑签名校验）；
//   - warnings / errors：不一致时给出中文原因（errors 非空 = 调用方必须拒绝下发）。
//
// **不一致时的默认口径：警告，不拒绝。** 理由（三个独立理由，任何一个都足以否掉"硬拒"）：
//
//  1. 实测结论可能缺失或不可信：非 Windows 控制端没有 WinVerifyTrust；Windows 上超时/证书链
//     问题会得到"Checked=false"，拿"这次没测出来"去硬拒一个合法驱动，代价是操作员在授权窗口内
//     什么都做不了；
//  2. 声明是人工写的：签名者常写简称（已被 signerMatches 的包含关系统一）、证书会轮换，
//     "不一致"多数是声明过期而不是驱动被换；
//  3. 既有行为：v1.3.4 的 byovd_load 对"声明签名者与实测不一致"就是给警告放行，硬拒会破坏既有链。
//
// 需要硬拒时由操作员在 manifest 里显式写 "require_signature": true —— 那是**操作员声明的口径**，
// 此时"声明要求签名有效但实测未通过/签名者不符"会变成 Errors（调用方一律拒绝下发）。
func SignatureConsistency(decl SignatureDeclaration, sig SignatureStatus) (*bool, []string, []string) {
	declared := strings.ToLower(strings.TrimSpace(decl.Declared))

	// 声明自相矛盾：要求签名有效，却声明"未签名" —— 这是配置错误，必须明确报出来，
	// 否则操作员会以为 require_signature 生效了而实际上它永远不会通过。
	if decl.Require && declared == SignatureUnsigned {
		return nil, nil, []string{
			`manifest 声明自相矛盾：require_signature=true（要求实测签名有效）但 signed=false（声明未签名）；请改正声明后再加载`,
		}
	}

	if !sig.Checked {
		// 没跑签名校验。分两种情况，处置**刻意不同**：
		//
		//   - 只是"声明了签名"：给警告（"声明未核对"）后放行 —— 声明是人工信息，
		//     拿"这次没测出来"去硬拒一个合法驱动，代价是操作员在授权窗口内什么都做不了；
		//   - 操作员显式要求"实测必须签名有效"（require_signature=true）：**fail-closed 拒绝** ——
		//     "无法确认"不等于"满足要求"，硬闸门不能因为校验不可用就静默放行（否则
		//     require_signature 在最需要它的场景下形同虚设）。结论不入缓存，可在
		//     GET /api/v1/drivers/{name}/verify 重试。
		if decl.Require {
			return nil, nil, []string{
				"manifest 要求签名有效（require_signature=true），但本次无法执行 Authenticode 签名校验" +
					"（非 Windows 平台 / wintrust 不可用 / 校验超时）：无法确认即不满足硬闸门，按 fail-closed 拒绝下发" +
					"（可在 GET /api/v1/drivers/{name}/verify 重试；超时结论不会被缓存）",
			}
		}
		if declared != SignatureUnset {
			return nil, []string{
				"签名声明无法核对：本次没有执行 Authenticode 签名校验（非 Windows 平台、wintrust 不可用或校验超时）；" +
					"manifest 里的签名信息只是人工声明，不代表实测结论（可在 GET /api/v1/drivers/{name}/verify 重试）",
			}, nil
		}
		return nil, nil, nil
	}

	var warns, errs []string

	// require_signature=true 是一个独立于声明三态的硬闸门：实测必须签名有效。
	if decl.Require && !sig.Signed {
		errs = append(errs, "manifest 要求签名有效（require_signature=true），但本机实测未通过 Authenticode 校验"+
			"（未签名/被篡改/证书不受信）：按操作员的显式声明拒绝加载")
	}

	switch declared {
	case SignatureSigned:
		consistent := sig.Signed
		switch {
		case sig.Signed && decl.Signer != "" && sig.Signer != "" && !signerMatches(decl.Signer, sig.Signer):
			consistent = false
			msg := fmt.Sprintf("签名声明与实测不一致：manifest 声明签名者 %q，本机实测签名者为 %q，请人工核对驱动来源",
				decl.Signer, sig.Signer)
			if decl.Require {
				errs = append(errs, msg+"（require_signature=true，按声明硬拒）")
			} else {
				warns = append(warns, msg)
			}
		case !sig.Signed:
			consistent = false
			msg := "签名声明与实测不一致：manifest 声明该驱动已签名，但本机实测未通过 Authenticode 校验（未签名/被篡改/证书不受信）"
			if decl.Require {
				// 上面已经加过同义错误，这里不重复。
				if len(errs) == 0 {
					errs = append(errs, msg+"（require_signature=true，按声明硬拒）")
				}
			} else {
				warns = append(warns, msg)
			}
		}
		return &consistent, warns, errs

	case SignatureUnsigned:
		consistent := !sig.Signed
		if sig.Signed {
			consistent = false
			warns = append(warns, "签名声明与实测不一致：manifest 声明该驱动未签名，但本机实测签名有效，请确认声明是否过期")
		}
		return &consistent, warns, errs

	default:
		// 未声明：把"实测缺签名"明确说出来（"缺签名要能看出来"），但没有声明就没有"一致/不一致"。
		if !sig.Signed {
			warns = append(warns, "manifest 未声明该驱动的签名信息，而本机实测未通过 Authenticode 校验（未签名或验证失败）："+
				`建议在 manifest.json 里补上 "signed": "签名者" 或 "signed": false，便于加载前一眼看出签名状态`)
		}
		if decl.Require {
			return boolPtr(sig.Signed), warns, errs
		}
		return nil, warns, errs
	}
}

// boolPtr 取地址（上面需要返回 *bool，直接写 &true 在 Go 里不合法）。
func boolPtr(v bool) *bool { return &v }
