package metrics

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var redactedKeys = map[string]struct{}{
	"private_key":     {},
	"private_key_hex": {},
	"identity_key":    {},
	"sdp":             {},
	"credential":      {},
	"username":        {},
	"password":        {},
	"payload":         {},
}

type Logger struct {
	mu   sync.Mutex
	side string
	out  *os.File
}

func New(side string) *Logger {
	return &Logger{side: side, out: os.Stdout}
}

func (l *Logger) Emit(event string, fields map[string]any) {
	record := make(map[string]any, len(fields)+3)
	for k, v := range fields {
		if isRedacted(k) {
			record[k] = "[REDACTED]"
			continue
		}
		record[k] = v
	}
	record["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	record["side"] = l.side
	record["event"] = event
	line, err := json.Marshal(record)
	if err != nil {
		line = []byte(fmt.Sprintf(`{"time":%q,"side":%q,"event":"log_marshal_error"}`, time.Now().UTC().Format(time.RFC3339Nano), l.side))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s\n", line)
}

func isRedacted(key string) bool {
	lk := strings.ToLower(key)
	for rk := range redactedKeys {
		if strings.Contains(lk, rk) {
			return true
		}
	}
	return false
}
