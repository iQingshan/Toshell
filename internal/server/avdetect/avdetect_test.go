package avdetect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadAndMatch 验证指纹库加载与进程名匹配。
func TestLoadAndMatch(t *testing.T) {
	// 从项目根 data/av_fingerprints.json 加载
	wd, _ := os.Getwd()
	root := filepath.Join(wd, "..", "..", "..")
	fp := filepath.Join(root, "data", "av_fingerprints.json")
	if _, err := os.Stat(fp); err != nil {
		t.Skipf("fingerprint file not found: %v", err)
	}
	os.Setenv("TOSHELL_AV_FINGERPRINTS", fp)
	if err := Load(); err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !Loaded() {
		t.Fatal("not loaded")
	}
	if ProcessCount() == 0 {
		t.Fatal("empty fingerprint index")
	}

	found := Match([]string{"360sd.exe", "svchost.exe", "notepad.exe", "MsMpEng.exe"})
	if len(found) == 0 {
		t.Fatal("expected matches")
	}
	names := make([]string, 0, len(found))
	for _, f := range found {
		names = append(names, f.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "360杀毒") {
		t.Errorf("360 safety guard not matched: %v", names)
	}
	if !strings.Contains(joined, "Windows Defender") {
		t.Errorf("Windows Defender not matched: %v", names)
	}
}

// TestDetectFromOutput 验证新/旧植入端输出兼容处理。
func TestDetectFromOutput(t *testing.T) {
	// 新植入端：进程名数组 -> 命中结果 JSON
	out := DetectFromOutput(`["360sd.exe","svchost.exe"]`)
	var found []Found
	if err := json.Unmarshal([]byte(out), &found); err != nil {
		t.Fatalf("result not valid JSON: %v (raw=%s)", err, out)
	}
	if len(found) != 1 || found[0].Name != "360杀毒" {
		t.Fatalf("unexpected result: %+v", found)
	}

	// 旧植入端：已是命中结果 -> 原样透传
	legacy := `[
  {
    "name": "火绒安全",
    "category": "杀毒软件",
    "process": "HipsTray.exe"
  }
]`
	if got := DetectFromOutput(legacy); got != legacy {
		t.Fatalf("legacy passthrough mismatch:\ngot=%s", got)
	}

	// 空/乱数据 -> 原样返回
	if DetectFromOutput("") != "" {
		t.Fatal("empty should stay empty")
	}
	if DetectFromOutput("not-json") != "not-json" {
		t.Fatal("invalid input should pass through")
	}
}
