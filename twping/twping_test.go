package twping

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/akprof2000/twping-go/owamp"
)

func TestParseDSCP(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint8
		ok   bool
	}{
		{"0", 0, true},
		{"46", 46, true},
		{"0x2e", 46, true},
		{"0X3F", 63, true},
		{"64", 0, false},
		{"abc", 0, false},
		{"-1", 0, false},
	} {
		got, err := parseDSCP(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseDSCP(%q) = %d, %v; ожидалось %d, ok=%v", tc.in, got, err, tc.want, tc.ok)
		}
	}
}

func TestParsePortRange(t *testing.T) {
	for _, tc := range []struct {
		in       string
		low, hig uint16
		ok       bool
	}{
		{"", 0, 0, true},
		{"8760", 8760, 8760, true},
		{"8760-8960", 8760, 8960, true},
		{" 8760 - 8960 ", 8760, 8960, true},
		{"8960-8760", 0, 0, false},
		{"abc", 0, 0, false},
		{"1-abc", 0, 0, false},
		{"70000", 0, 0, false},
	} {
		got, err := parsePortRange(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parsePortRange(%q): err=%v, ожидалось ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && (got.Low != tc.low || got.High != tc.hig) {
			t.Errorf("parsePortRange(%q) = %d-%d, ожидалось %d-%d", tc.in, got.Low, got.High, tc.low, tc.hig)
		}
	}
}

func TestParseAuthMode(t *testing.T) {
	for _, tc := range []struct {
		in, identity string
		want         uint32
		ok           bool
	}{
		{"", "", owamp.ModeOpen, true},
		{"", "alice", owamp.TWPDefaultOfferedMode, true},
		{"E", "alice", owamp.ModeEncrypted, true},
		{"ae", "alice", owamp.ModeAuth | owamp.ModeEncrypted, true},
		{"MO", "", owamp.ModeMixed | owamp.ModeOpen, true},
		{"X", "", 0, false},
	} {
		got, err := parseAuthMode(tc.in, tc.identity)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseAuthMode(%q, %q) = 0x%x, %v; ожидалось 0x%x, ok=%v",
				tc.in, tc.identity, got, err, tc.want, tc.ok)
		}
	}
}

func TestVerboseFlag(t *testing.T) {
	got := normalizeVerbose([]string{"-c", "5", "-v", "-v10", "-v=3", "host"})
	want := []string{"-c", "5", "-v=on", "-v=10", "-v=3", "host"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("normalizeVerbose = %v, ожидалось %v", got, want)
	}

	for _, tc := range []struct {
		in    string
		on    bool
		limit uint64
	}{
		{"", false, 0},
		{"on", true, 0},
		{"10", true, 10},
		{"abc", true, 0},
	} {
		on, limit := parseVerbose(tc.in)
		if on != tc.on || limit != tc.limit {
			t.Errorf("parseVerbose(%q) = %v, %d; ожидалось %v, %d", tc.in, on, limit, tc.on, tc.limit)
		}
	}
}

func TestReadPassphrase(t *testing.T) {
	dir := t.TempDir()
	multi := filepath.Join(dir, "multi")
	if err := os.WriteFile(multi, []byte("# комментарий\nalice secret one\r\nbob secret two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	single := filepath.Join(dir, "single")
	if err := os.WriteFile(single, []byte("  lonely phrase \n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := readPassphrase(multi, "bob"); err != nil || string(got) != "secret two" {
		t.Errorf("readPassphrase(multi, bob) = %q, %v", got, err)
	}
	if got, err := readPassphrase(multi, "alice"); err != nil || string(got) != "secret one" {
		t.Errorf("readPassphrase(multi, alice) = %q, %v", got, err)
	}
	if _, err := readPassphrase(multi, "carol"); err == nil {
		t.Error("readPassphrase(multi, carol) должен вернуть ошибку")
	}
	if got, err := readPassphrase(single, ""); err != nil || string(got) != "lonely phrase" {
		t.Errorf("readPassphrase(single, \"\") = %q, %v", got, err)
	}
	if _, err := readPassphrase("", "alice"); err == nil {
		t.Error("без файла парольной фразы ожидалась ошибка")
	}
}

func TestRunArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"-c", "0", "host"},
		{"-i", "0", "host"},
		{"-4", "-6", "host"},
		{"-n", "x", "host"},
		{"-D", "99", "host"},
		{"a", "b", "c"},
	} {
		var out, errOut bytes.Buffer
		if err := Run(context.Background(), args, &out, &errOut); err == nil {
			t.Errorf("Run(%v) должен вернуть ошибку", args)
		}
	}
	var out, errOut bytes.Buffer
	if err := Run(context.Background(), []string{"-h"}, &out, &errOut); err != nil {
		t.Errorf("Run(-h) = %v", err)
	}
	if !strings.Contains(errOut.String(), "использование:") {
		t.Errorf("справка не напечатана:\n%s", errOut.String())
	}
}

// Отмена контекста должна прерывать замер уже на рукопожатии: сервер принял
// TCP-соединение, но приветствия не шлёт.
func TestRunCancelledDuringHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				conn.Close()
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)

	var out, errOut bytes.Buffer
	start := time.Now()
	err = Run(ctx, []string{"-c", "1", "127.0.0.1", ln.Addr().String()}, &out, &errOut)
	if !errors.Is(err, errInterrupted) {
		t.Fatalf("ожидалось %v, получено %v", errInterrupted, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("отмена подействовала только через %v", elapsed)
	}
}
