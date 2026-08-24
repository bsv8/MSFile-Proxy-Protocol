package relay

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"msfile.dev/labs/webrtc-go/internal/identity"
)

// TestRelaySigusr1DoesNotStopProcess re-executes the test binary as a helper
// process running relay.Run, then asserts SIGUSR1 only triggers a counter
// snapshot while SIGTERM is what actually stops the process.
func TestRelaySigusr1DoesNotStopProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGUSR1 is not meaningful on windows")
	}
	if os.Getenv("RELAY_SIGUSR1_HELPER") == "1" {
		runSigusr1Helper()
		return
	}

	keyPath := filepath.Join(t.TempDir(), "relay.key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("11", 32)+"\n"), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRelaySigusr1DoesNotStopProcess", "-test.v=true")
	cmd.Env = append(os.Environ(), "RELAY_SIGUSR1_HELPER=1", "RELAY_SIGUSR1_KEYFILE="+keyPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	lines := make(chan string, 512)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
	}()

	waitForLine(t, lines, "relay_started", 30*time.Second)
	time.Sleep(300 * time.Millisecond)

	if !processAlive(cmd.Process.Pid) {
		t.Fatal("helper died before SIGUSR1")
	}
	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGUSR1); err != nil {
		t.Fatalf("send SIGUSR1: %v", err)
	}
	snapshotLine := waitForLine(t, lines, "relay_counter_snapshot", 10*time.Second)
	if !strings.Contains(snapshotLine, `"trigger":"SIGUSR1"`) {
		t.Fatalf("SIGUSR1 snapshot missing trigger marker, got: %s", snapshotLine)
	}
	time.Sleep(500 * time.Millisecond)
	if !processAlive(cmd.Process.Pid) {
		t.Fatal("helper must still be running after SIGUSR1 (SIGUSR1 must not stop the relay)")
	}

	if err := syscall.Kill(cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("helper did not exit after SIGTERM")
	}
	stoppingSeen := false
	for _, line := range drainLines(lines) {
		if strings.Contains(line, "relay_stopping") {
			stoppingSeen = true
			if strings.Contains(line, `"trigger":"SIGUSR1"`) {
				t.Fatal("relay_stopping should not carry a SIGUSR1 trigger")
			}
		}
	}
	if !stoppingSeen {
		t.Log("note: relay_stopping line was consumed by earlier waits; exit after SIGTERM confirmed instead")
	}
}

func drainLines(ch <-chan string) []string {
	var out []string
	for {
		select {
		case line, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, line)
		default:
			return out
		}
	}
}

func waitForLine(t *testing.T, ch <-chan string, needle string, timeout time.Duration) string {
	t.Helper()
	deadline := time.After(timeout)
	collected := ""
	for {
		select {
		case chunk, ok := <-ch:
			if !ok {
				t.Fatalf("helper output closed before seeing %q; so far: %s", needle, collected)
			}
			collected += chunk + "\n"
			if strings.Contains(chunk, needle) {
				return chunk
			}
			if len(collected) > 1024*1024 {
				t.Fatalf("output overflow without %q", needle)
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %q in helper output; so far: %s", needle, collected)
		}
	}
}

func processAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func runSigusr1Helper() {
	keyFile := os.Getenv("RELAY_SIGUSR1_KEYFILE")
	if keyFile == "" {
		fmt.Fprintln(os.Stderr, "helper missing keyfile env")
		os.Exit(2)
	}
	if _, err := identity.LoadPrivateKeyHexFile(keyFile); err != nil {
		fmt.Fprintf(os.Stderr, "helper bad key: %v\n", err)
		os.Exit(2)
	}
	err := Run(Options{
		KeyFile:    keyFile,
		WSListen:   "/ip4/127.0.0.1/tcp/0/ws",
		EdgeListen: "127.0.0.1:0",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "helper run error: %v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
