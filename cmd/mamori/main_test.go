package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEgressListsOnlyReadMethodsExceptOSVAPI(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"egress"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if strings.Contains(line, "POST") && !strings.HasPrefix(line, "api.osv.dev") {
			t.Errorf("only api.osv.dev may take POST: %s", line)
		}
		if strings.HasPrefix(line, "api.osv.dev") && !strings.Contains(line, "--online only") {
			t.Errorf("api.osv.dev must be --online only: %s", line)
		}
	}
}

func TestFlagConflicts(t *testing.T) {
	for _, args := range [][]string{
		{"scan", "--online", "--offline"},
		{"scan", "--offline", "--github", "o"},
		{"nonsense"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
