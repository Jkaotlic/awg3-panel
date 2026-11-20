package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDryRunCLIAndSafeErrors(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"prepare", "--dry-run", "--root", t.TempDir(), "--endpoint", "203.0.113.10", "--egress", "eth0"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "10.66.0.1:8081") || strings.Contains(out.String(), "PrivateKey") {
		t.Fatal("unsafe or missing result")
	}
	if err := run([]string{"unknown"}, &out); err == nil {
		t.Fatal("unknown command accepted")
	}
}
