package relay

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ma "github.com/multiformats/go-multiaddr"

	"msfile.dev/labs/webrtc-go/internal/metrics"
)

func TestCountingReaderWriterLiveTotals(t *testing.T) {
	pr, pw := io.Pipe()
	cr := &countingReader{r: pr}
	cw := &countingWriter{w: pw}

	payload := make([]byte, 4096)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	writeDone := make(chan struct{})
	go func() {
		defer close(writeDone)
		for i := 0; i < 8; i++ {
			if _, err := cw.Write(payload); err != nil {
				t.Errorf("write: %v", err)
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	total := 0
	for total < 4096*8 {
		n, err := cr.Read(buf)
		total += n
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	<-writeDone
	_ = pw.Close()

	if got := cw.n.Load(); got != uint64(4096*8) {
		t.Fatalf("writer counted %d, want %d", got, uint64(4096*8))
	}
	if got := cr.n.Load(); got != uint64(4096*8) {
		t.Fatalf("reader counted %d, want %d", got, uint64(4096*8))
	}
}

func startFakeUpstream(t *testing.T, bytesToServe int, chunkDelay time.Duration) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveFakeUpstreamConn(ctx, conn, bytesToServe, chunkDelay)
		}
	}()
	return listener.Addr().String()
}

func serveFakeUpstreamConn(ctx context.Context, conn net.Conn, bytesToServe int, chunkDelay time.Duration) {
	defer conn.Close()
	written := 0
	buf := make([]byte, 1024)
	for written < bytesToServe {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n := len(buf)
		if remaining := bytesToServe - written; remaining < n {
			n = remaining
		}
		if _, werr := conn.Write(buf[:n]); werr != nil {
			return
		}
		written += n
		time.Sleep(chunkDelay)
	}
}

func TestEdgeProxyCountersAreLiveDuringTransfer(t *testing.T) {
	const totalBytes = 512 * 1024
	upstream := startFakeUpstream(t, totalBytes, 2*time.Millisecond)

	log := silentRelayLogger()
	ep := startEdgeProxy(log, "127.0.0.1:0", mustMultiaddrFromTCP(upstream))
	if ep == nil {
		t.Fatal("edge proxy failed to start")
	}
	t.Cleanup(ep.stop)

	conn, err := net.DialTimeout("tcp", ep.listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}

	var readTotal atomic.Uint64
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 32*1024)
		var got uint64
		for {
			n, rerr := conn.Read(buf)
			got += uint64(n)
			readTotal.Store(got)
			if rerr != nil || got >= totalBytes {
				return
			}
		}
	}()

	midSeen := false
	graceStarted := false
	var graceDeadline time.Time
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	hardDeadline := time.After(30 * time.Second)
	for !midSeen {
		select {
		case <-readerDone:
			if !midSeen {
				t.Fatal("never observed live counter movement while transfer was still in progress")
			}
			return
		case <-hardDeadline:
			t.Fatal("timed out observing live counters during partial transfer")
		case <-ticker.C:
			partial := readTotal.Load()
			if partial == 0 || partial >= totalBytes {
				continue
			}
			if !graceStarted {
				graceStarted = true
				graceDeadline = time.Now().Add(500 * time.Millisecond)
			}
			in, out, active := ep.counter.snapshot()
			if out == 0 {
				if time.Now().After(graceDeadline) {
					t.Fatalf("live out counter still zero 500ms into partial transfer (read=%d/%d)", partial, uint64(totalBytes))
				}
				continue
			}
			if in != 0 || active != 1 {
				t.Fatalf("mid-transfer counters unexpected: in=%d out=%d active=%d", in, out, active)
			}
			midSeen = true
		}
	}
	<-readerDone
	waitForCounter(t, ep.counter, totalBytes, 5*time.Second)

	inFinal, outFinal, _ := ep.counter.snapshot()
	if outFinal != totalBytes {
		t.Fatalf("final out=%d want %d", outFinal, totalBytes)
	}
	if inFinal != 0 {
		t.Fatalf("client sent nothing upstream, but in=%d", inFinal)
	}
}

func TestEdgeProxyShutdownWaitsForActiveConnsAndCountsRaceSafe(t *testing.T) {
	const perConnBytes = 256 * 1024
	const connCount = 4
	upstream := startFakeUpstream(t, perConnBytes, 0)

	log := silentRelayLogger()
	ep := startEdgeProxy(log, "127.0.0.1:0", mustMultiaddrFromTCP(upstream))
	if ep == nil {
		t.Fatal("edge proxy failed to start")
	}

	stopPolling := make(chan struct{})
	var pollWG sync.WaitGroup
	pollWG.Add(1)
	go func() {
		defer pollWG.Done()
		for {
			select {
			case <-stopPolling:
				return
			default:
				_, _, _ = ep.counter.snapshot()
			}
		}
	}()

	var readerWG sync.WaitGroup
	for i := 0; i < connCount; i++ {
		conn, derr := net.DialTimeout("tcp", ep.listener.Addr().String(), 5*time.Second)
		if derr != nil {
			t.Fatalf("dial edge: %v", derr)
		}
		readerWG.Add(1)
		go func(c net.Conn) {
			defer readerWG.Done()
			got := 0
			buf := make([]byte, 16*1024)
			for got < perConnBytes {
				n, rerr := c.Read(buf)
				got += n
				if rerr != nil {
					return
				}
			}
		}(conn)
	}
	readerWG.Wait()
	waitForCounter(t, ep.counter, uint64(perConnBytes*connCount), 5*time.Second)
	close(stopPolling)
	pollWG.Wait()

	in, out, _ := ep.counter.snapshot()
	if out != uint64(perConnBytes*connCount) {
		t.Fatalf("out=%d want %d", out, uint64(perConnBytes*connCount))
	}
	if in != 0 {
		t.Fatalf("in=%d want 0", in)
	}

	stopDone := make(chan struct{})
	go func() {
		ep.stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-time.After(15 * time.Second):
		t.Fatal("edge proxy stop() did not return")
	}
	if _, _, active := ep.counter.snapshot(); active != 0 {
		t.Fatalf("active=%d want 0 after stop", active)
	}
}

func TestEdgeProxyStopDrainsActiveConns(t *testing.T) {
	upstream := startFakeUpstream(t, 4*1024*1024, time.Millisecond)

	log := silentRelayLogger()
	ep := startEdgeProxy(log, "127.0.0.1:0", mustMultiaddrFromTCP(upstream))
	if ep == nil {
		t.Fatal("edge proxy failed to start")
	}

	conn, derr := net.DialTimeout("tcp", ep.listener.Addr().String(), 5*time.Second)
	if derr != nil {
		t.Fatalf("dial edge: %v", derr)
	}
	readDone := make(chan int)
	go func() {
		got := 0
		buf := make([]byte, 16*1024)
		for {
			n, rerr := conn.Read(buf)
			got += n
			if rerr != nil {
				readDone <- got
				return
			}
		}
	}()
	time.Sleep(100 * time.Millisecond)

	started := time.Now()
	ep.stop()
	if elapsed := time.Since(started); elapsed > 12*time.Second {
		t.Fatalf("stop() took %s with an active conn", elapsed)
	}
	_, _, active := ep.counter.snapshot()
	if active != 0 {
		t.Fatalf("active=%d want 0 after stop", active)
	}
	select {
	case got := <-readDone:
		t.Logf("reader observed %d bytes before stop closed the conn", got)
	case <-time.After(5 * time.Second):
		t.Fatal("reader goroutine did not observe connection close")
	}
}

func TestByteCounterConcurrentSnapshotAndAdd(t *testing.T) {
	counter := &byteCounter{}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10000; i++ {
				counter.add(1, 2)
				_, _, _ = counter.snapshot()
			}
		}()
	}
	wg.Wait()
	in, out, active := counter.snapshot()
	if in != 80000 || out != 160000 {
		t.Fatalf("totals mismatch: in=%d out=%d", in, out)
	}
	if active != 0 {
		t.Fatalf("active=%d want 0", active)
	}
}

func waitForCounter(t *testing.T, counter *byteCounter, wantOut uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, out, _ := counter.snapshot(); out >= wantOut {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	in, out, _ := counter.snapshot()
	t.Fatalf("counter did not reach out=%d within %s (last in=%d out=%d)", wantOut, timeout, in, out)
}

func mustMultiaddrFromTCP(addr string) ma.Multiaddr {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	maStr := fmt.Sprintf("/ip4/%s/tcp/%s", host, port)
	parsed, perr := ma.NewMultiaddr(maStr)
	if perr != nil {
		panic(perr)
	}
	return parsed
}

func silentRelayLogger() *metrics.Logger {
	return metrics.New("test")
}
