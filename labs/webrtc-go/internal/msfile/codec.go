package msfile

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

const (
	ProtocolID        = "/msfile/1.0.0"
	WireVersion       = uint64(1)
	KindStatRequest   = uint64(1)
	KindStatResponse  = uint64(2)
	KindReadRequest   = uint64(3)
	KindReadResponse  = uint64(4)
	KindReadCancelled = uint64(5)
	KindErrorResponse = uint64(255)
	MaxHeaderBytes    = 65536
	MaxContentBytes   = 16777216
)

type Request struct {
	Kind     uint64
	ID       uint64
	Hash     [32]byte
	MaxPrice uint64
}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = (cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		MaxNestedLevels:  4,
		MaxArrayElements: 16,
	}).DecMode()
	if err != nil {
		panic(err)
	}
}

func ReadRequest(r io.ByteReader) (Request, error) {
	header, err := readHeader(r)
	if err != nil {
		return Request{}, err
	}
	var fields []any
	if err := decMode.Unmarshal(header, &fields); err != nil {
		return Request{}, fmt.Errorf("CBOR Header 无效: %w", err)
	}
	canonical, err := encMode.Marshal(fields)
	if err != nil || !bytes.Equal(canonical, header) {
		return Request{}, errors.New("CBOR Header 不是 deterministic canonical 编码")
	}
	if len(fields) < 2 {
		return Request{}, errors.New("Header 字段不足")
	}
	version, ok := fields[0].(uint64)
	if !ok || version != WireVersion {
		return Request{}, errors.New("不支持的 wire_version")
	}
	kind, ok := fields[1].(uint64)
	if !ok {
		return Request{}, errors.New("wire_kind 类型错误")
	}
	want := 4
	if kind == KindReadRequest {
		want = 5
	}
	if kind != KindStatRequest && kind != KindReadRequest {
		return Request{}, errors.New("客户端请求 Kind 不受支持")
	}
	if len(fields) != want {
		return Request{}, fmt.Errorf("Kind %d Header 必须有 %d 个字段", kind, want)
	}
	id, ok := fields[2].(uint64)
	if !ok || id == 0 {
		return Request{}, errors.New("request_id 必须是非零 uint64")
	}
	hashBytes, ok := fields[3].([]byte)
	if !ok || len(hashBytes) != 32 {
		return Request{}, errors.New("content_hash 必须是 32 字节 bstr")
	}
	request := Request{Kind: kind, ID: id}
	copy(request.Hash[:], hashBytes)
	if kind == KindReadRequest {
		price, ok := fields[4].(uint64)
		if !ok {
			return Request{}, errors.New("max_price_satoshis 必须是 uint64")
		}
		request.MaxPrice = price
	}
	return request, nil
}

func readHeader(r io.ByteReader) ([]byte, error) {
	var encoded [3]byte
	for i := 0; i < len(encoded); i++ {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		encoded[i] = b
		if b&0x80 == 0 {
			length, n := binary.Uvarint(encoded[:i+1])
			if n <= 0 || length == 0 || length > MaxHeaderBytes {
				return nil, errors.New("Header 长度超出 1..65536")
			}
			var shortest [10]byte
			if binary.PutUvarint(shortest[:], length) != i+1 {
				return nil, errors.New("Header 长度不是最短 uvarint 编码")
			}
			header := make([]byte, int(length))
			if _, err := io.ReadFull(byteReaderAsReader{r}, header); err != nil {
				return nil, fmt.Errorf("Header 被截断: %w", err)
			}
			return header, nil
		}
	}
	return nil, errors.New("Header 长度 uvarint 超过 3 字节")
}

type byteReaderAsReader struct{ io.ByteReader }

func (r byteReaderAsReader) Read(p []byte) (int, error) {
	for i := range p {
		b, err := r.ReadByte()
		if err != nil {
			return i, err
		}
		p[i] = b
	}
	return len(p), nil
}

func WriteFrame(w io.Writer, fields []any, attachment io.Reader, attachmentLength int64) error {
	header, err := encMode.Marshal(fields)
	if err != nil {
		return err
	}
	if len(header) == 0 || len(header) > MaxHeaderBytes {
		return errors.New("响应 Header 尺寸超限")
	}
	var prefix [10]byte
	n := binary.PutUvarint(prefix[:], uint64(len(header)))
	if _, err := w.Write(prefix[:n]); err != nil {
		return err
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if attachmentLength == 0 {
		return nil
	}
	if attachment == nil || attachmentLength < 0 || attachmentLength > MaxContentBytes {
		return errors.New("响应 attachment 参数非法")
	}
	buffer := make([]byte, 16*1024)
	limited := &io.LimitedReader{R: attachment, N: attachmentLength}
	if _, err = io.CopyBuffer(w, limited, buffer); err != nil {
		return err
	}
	if limited.N != 0 {
		return errors.New("响应 attachment 短于声明尺寸")
	}
	return nil
}

func StatAvailable(id uint64, filename string, size int64, mediaType string) []any {
	return []any{WireVersion, KindStatResponse, id, uint64(1), filename, uint64(size), mediaType}
}

func StatAbsent(id uint64) []any {
	return []any{WireVersion, KindStatResponse, id, uint64(2)}
}

func ReadSuccess(id uint64, hash [32]byte, size int64) []any {
	return []any{WireVersion, KindReadResponse, id, hash[:], uint64(size)}
}

func ReadCancelled(id uint64, hash [32]byte, replacedBy uint64) []any {
	return []any{WireVersion, KindReadCancelled, id, hash[:], replacedBy}
}

func Error(kind, id uint64, code, message string, retryAfter uint64) []any {
	if len(message) > 1024 {
		message = message[:1024]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	return []any{WireVersion, KindErrorResponse, kind, id, code, message, retryAfter}
}

// EncodeRequest 把请求字段数组编码为完整 Frame 并写入 w。
// 供客户端实现复用同一套 deterministic CBOR 与 framing 规则。
func EncodeRequest(w io.Writer, fields []any) error {
	return WriteFrame(w, fields, nil, 0)
}

// DecodeResponseFields 从流中读取一个响应 Frame 的 CBOR 字段数组。
// attachment（若有）留在流中，由调用方按 content_length 继续读取。
func DecodeResponseFields(r io.Reader) ([]any, error) {
	buffered, ok := r.(io.ByteReader)
	if !ok {
		buffered = bufio.NewReader(r)
	}
	header, err := readHeader(buffered)
	if err != nil {
		return nil, err
	}
	var fields []any
	if err := decMode.Unmarshal(header, &fields); err != nil {
		return nil, fmt.Errorf("CBOR Header 无效: %w", err)
	}
	return fields, nil
}
