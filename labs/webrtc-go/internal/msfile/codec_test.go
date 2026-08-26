package msfile

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf8"
)

func framedHeader(t *testing.T, fields []any) []byte {
	t.Helper()
	header, err := encMode.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var prefix [10]byte
	n := binary.PutUvarint(prefix[:], uint64(len(header)))
	return append(prefix[:n], header...)
}

func TestReadCanonicalRequests(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 32)
	for _, test := range []struct {
		fields []any
		kind   uint64
		price  uint64
	}{
		{[]any{uint64(1), uint64(1), uint64(7), hash}, KindStatRequest, 0},
		{[]any{uint64(1), uint64(3), uint64(8), hash, uint64(99)}, KindReadRequest, 99},
	} {
		request, err := ReadRequest(bytes.NewBuffer(framedHeader(t, test.fields)))
		if err != nil {
			t.Fatalf("解码请求: %v", err)
		}
		if request.Kind != test.kind || request.MaxPrice != test.price || !bytes.Equal(request.Hash[:], hash) {
			t.Fatalf("请求字段错误: %+v", request)
		}
	}
}

func TestRejectNonCanonicalCBORAndUvarint(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 32)
	canonical := framedHeader(t, []any{uint64(1), uint64(1), uint64(7), hash})
	// 0x01 改为非最短的 0x18 0x01，并同步 Header 长度。
	nonCanonical := append([]byte{}, canonical...)
	nonCanonical[0]++
	nonCanonical = append(nonCanonical[:2], append([]byte{0x18, 0x01}, nonCanonical[3:]...)...)
	if _, err := ReadRequest(bytes.NewBuffer(nonCanonical)); err == nil {
		t.Fatal("应拒绝非 deterministic CBOR")
	}
	overlongLength := append([]byte{canonical[0] | 0x80, 0x00}, canonical[1:]...)
	if _, err := ReadRequest(bytes.NewBuffer(overlongLength)); err == nil {
		t.Fatal("应拒绝非最短 uvarint")
	}
}

func TestWriteFrameRejectsTruncatedAttachment(t *testing.T) {
	var output bytes.Buffer
	err := WriteFrame(&output, []any{WireVersion, KindReadResponse, uint64(1), make([]byte, 32), uint64(4)}, bytes.NewReader([]byte{1, 2}), 4)
	if err == nil {
		t.Fatal("attachment 少于声明长度时必须失败")
	}
}

// ---------- T19：deterministic CBOR 与 framing 严格性补充 ----------

func TestRejectIndefiniteLengthHeader(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 32)
	// 手工构造 indefinite-length array 开头（0x9f）的 Header。
	indefinite := append([]byte{0x9f},
		append([]byte{0x01}, append([]byte{0x01}, []byte{}...)...)...)
	indefinite = append(indefinite, 0xff) // break code
	frame := framedRaw(t, indefinite)
	if _, err := ReadRequest(bytes.NewBuffer(frame)); err == nil {
		t.Fatal("应拒绝 indefinite-length CBOR Header")
	}
	_ = hash
}

func TestRejectWrongArrayLengthAndFields(t *testing.T) {
	hash := bytes.Repeat([]byte{0xab}, 32)
	cases := []struct {
		name   string
		fields []any
	}{
		{"wire_version 不是 1", []any{uint64(2), uint64(1), uint64(7), hash}},
		{"未知 Kind", []any{uint64(1), uint64(9), uint64(7), hash}},
		{"Stat 多一个字段", []any{uint64(1), uint64(1), uint64(7), hash, uint64(1)}},
		{"Stat 少一个字段", []any{uint64(1), uint64(1), uint64(7)}},
		{"request_id 为 0", []any{uint64(1), uint64(1), uint64(0), hash}},
		{"content_hash 不是 32 字节", []any{uint64(1), uint64(1), uint64(7), hash[:31]}},
		{"content_hash 是 text 而非 bstr", []any{uint64(1), uint64(1), uint64(7), "ab"}},
		{"Read 少 max_price", []any{uint64(1), uint64(3), uint64(8), hash}},
		{"max_price 类型错误", []any{uint64(1), uint64(3), uint64(8), hash, int64(-1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadRequest(bytes.NewBuffer(framedHeader(t, tc.fields))); err == nil {
				t.Fatalf("应拒绝：%s", tc.name)
			}
		})
	}
}

func TestRejectBadFramingLengths(t *testing.T) {
	// 长度为 0 的 uvarint。
	zero := []byte{0x00}
	if _, err := ReadRequest(bytes.NewBuffer(zero)); err == nil {
		t.Fatal("应拒绝长度为 0 的 Header")
	}
	// uvarint 编码超过 3 字节。
	long := []byte{0x80, 0x80, 0x80, 0x01}
	if _, err := ReadRequest(bytes.NewBuffer(long)); err == nil {
		t.Fatal("应拒绝超过 3 字节的长度前缀")
	}
	// 非最短编码：65536 用 3 字节表示但值本身超上限。
	tooBig := []byte{0x81, 0x82, 0x84} // 无法构成合法小值，应报错
	if _, err := ReadRequest(bytes.NewBuffer(tooBig)); err == nil {
		t.Fatal("应拒绝非法的长度值")
	}
	// Header 声明截断。
	canonical := framedHeader(t, []any{uint64(1), uint64(1), uint64(7), bytes.Repeat([]byte{0xab}, 32)})
	truncated := canonical[:len(canonical)-5]
	if _, err := ReadRequest(bytes.NewBuffer(truncated)); err == nil {
		t.Fatal("应拒绝被截断的 Header")
	}
}

func TestWriteFrameAttachmentLimits(t *testing.T) {
	var output bytes.Buffer
	// 超过 MaxContentBytes 的声明必须被拒绝。
	err := WriteFrame(&output,
		[]any{WireVersion, KindReadResponse, uint64(1), make([]byte, 32), uint64(MaxContentBytes) + 1},
		bytes.NewReader(make([]byte, 16)), int64(MaxContentBytes)+1)
	if err == nil {
		t.Fatal("attachment 声明超过 MaxContentBytes 必须失败")
	}
	// 正常小附件写入成功且字节数正确。
	output.Reset()
	payload := []byte{9, 8, 7, 6}
	fields := ReadSuccess(3, [32]byte{}, int64(len(payload)))
	before := output.Len()
	if err := WriteFrame(&output, fields, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("写入合法 Frame 失败: %v", err)
	}
	if output.Len() <= before || !bytes.HasSuffix(output.Bytes(), payload) {
		t.Fatal("Frame 输出应以完整 attachment 结尾")
	}
}

func TestErrorMessageTruncatedOnUtf8Boundary(t *testing.T) {
	message := strings.Repeat("汉", 700) // 2100 字节，超过 1024 上限
	fields := Error(KindStatRequest, 1, "bad_request", message, 0)
	encoded, err := encMode.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	// 反解出 message 字段验证长度与合法性。
	var decoded []any
	if err := decMode.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	text, ok := decoded[5].(string)
	if !ok {
		t.Fatal("error_message 应是 text string")
	}
	if len(text) > 1024 {
		t.Fatalf("error_message 应不超过 1024 字节，实际 %d", len(text))
	}
	if !utf8.ValidString(text) {
		t.Fatal("截断后的 error_message 必须仍是合法 UTF-8")
	}
}

// framedRaw 把任意原始 Header 字节按 framing 规则包一层长度前缀。
func framedRaw(t *testing.T, header []byte) []byte {
	t.Helper()
	var prefix [10]byte
	n := binary.PutUvarint(prefix[:], uint64(len(header)))
	return append(prefix[:n], header...)
}

// decodeRawHeader 从完整 Frame 字节解出 CBOR 字段（测试辅助）。
func decodeRawHeader(data []byte) ([]any, error) {
	var out []any
	err := decMode.Unmarshal(data[1:], &out)
	return out, err
}
