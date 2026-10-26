package version

import "testing"

func TestParse(t *testing.T) {
	for in, want := range map[string]string{
		"v22.23.4":         "22.23.4",
		"1.4.4":            "1.4.4",
		"Python 3.11.15":   "3.11.15",
		"bun 1.3.14\n":     "1.3.14",
		"PHP 8.3.36 (cli)": "8.3.36",
		"26.12.1_1":        "26.12.1",
	} {
		v, ok := Parse(in)
		if !ok || v.Raw != want {
			t.Errorf("Parse(%q) = %q,%v want %q", in, v.Raw, ok, want)
		}
	}
	if _, ok := Parse("none"); ok {
		t.Error("Parse(none) should fail")
	}
}

func TestAgainst(t *testing.T) {
	node := []string{"22.23.4", "24.22.1", "26.12.1"}
	cases := []struct {
		in     string
		fixed  []string
		branch string
		want   Status
	}{
		{"v22.22.2", node, "major", Vulnerable},
		{"v22.23.4", node, "major", Fixed},
		{"v26.12.1", node, "major", Fixed},
		{"v20.20.1", node, "major", NoFixInLine},
		{"v28.0.0", node, "major", Fixed},
		{"1.3.14", []string{"1.4.4"}, "none", Vulnerable},
		{"1.4.4", []string{"1.4.4"}, "none", Fixed},
		{"1.2.0", []string{"1.0.10", "1.1.1", "1.2.1"}, "minor", Vulnerable},
		{"1.2.1", []string{"1.0.10", "1.1.1", "1.2.1"}, "minor", Fixed},
		{"8.1.30", []string{"8.2.35", "8.3.36"}, "minor", NoFixInLine},
		{"garbage", node, "major", Unknown},
	}
	for _, c := range cases {
		if got, _ := Against(c.in, c.fixed, c.branch); got != c.want {
			t.Errorf("Against(%s, %v, %s) = %s, want %s", c.in, c.fixed, c.branch, got, c.want)
		}
	}
}
