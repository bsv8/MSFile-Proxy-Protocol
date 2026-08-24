package labproto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	ProtocolIdentity = "/msfile-lab/identity/1.0.0"
	ProtocolEcho     = "/msfile-lab/echo/1.0.0"
	ProtocolBytes    = "/msfile-lab/bytes/1.0.0"

	MaxWriteChunkBytes  = 16384
	DefaultBlockBytes   = 262144
	EchoMaxPayloadBytes = 64 * 1024 * 1024

	MaxTotalBytes = uint64(8) << 30

	bytesRequestSize   = 20
	bytesHeaderLen     = 8
	bytesTrailerLen    = 32
	maxConcurrentBytes = 8
)

type BytesRequest struct {
	TotalBytes        uint64
	LogicalBlockBytes uint32
	Seed              uint64
}

func EncodeEchoFrame(payload []byte) []byte {
	if uint64(len(payload)) > EchoMaxPayloadBytes {
		panic(fmt.Sprintf("echo payload too large: %d", len(payload)))
	}
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(out[0:], uint64(len(payload)))
	copy(out[8:], payload)
	return out
}

func ParseEchoFrame(frame []byte) ([]byte, error) {
	if len(frame) < 8 {
		return nil, fmt.Errorf("echo frame too short: %d bytes", len(frame))
	}
	length := binary.BigEndian.Uint64(frame[0:])
	if length > EchoMaxPayloadBytes {
		return nil, fmt.Errorf("echo frame length out of range: %d", length)
	}
	if uint64(len(frame)-8) != length {
		return nil, fmt.Errorf("echo frame length mismatch: header=%d body=%d", length, len(frame)-8)
	}
	return frame[8:], nil
}

func EncodeBytesRequest(req BytesRequest) ([]byte, error) {
	if req.LogicalBlockBytes == 0 {
		return nil, fmt.Errorf("logical block size must not be zero")
	}
	out := make([]byte, bytesRequestSize)
	binary.BigEndian.PutUint64(out[0:], req.TotalBytes)
	binary.BigEndian.PutUint32(out[8:], req.LogicalBlockBytes)
	binary.BigEndian.PutUint64(out[12:], req.Seed)
	return out, nil
}

func ParseBytesRequest(data []byte) (BytesRequest, error) {
	if len(data) != bytesRequestSize {
		return BytesRequest{}, fmt.Errorf("bytes request must be exactly %d bytes, got %d", bytesRequestSize, len(data))
	}
	req := BytesRequest{
		TotalBytes:        binary.BigEndian.Uint64(data[0:]),
		LogicalBlockBytes: binary.BigEndian.Uint32(data[8:]),
		Seed:              binary.BigEndian.Uint64(data[12:]),
	}
	if req.LogicalBlockBytes == 0 {
		return BytesRequest{}, fmt.Errorf("logical block size must not be zero")
	}
	if req.TotalBytes > MaxTotalBytes {
		return BytesRequest{}, fmt.Errorf("total bytes out of lab range: %d > %d", req.TotalBytes, MaxTotalBytes)
	}
	return req, nil
}

func EncodeBytesResponseHeader(totalBytes uint64) []byte {
	out := make([]byte, bytesHeaderLen)
	binary.BigEndian.PutUint64(out[0:], totalBytes)
	return out
}

func ParseBytesResponsePrefix(data []byte) (uint64, error) {
	if len(data) < bytesHeaderLen {
		return 0, fmt.Errorf("bytes response prefix incomplete: got %d bytes, want %d", len(data), bytesHeaderLen)
	}
	return binary.BigEndian.Uint64(data[0:]), nil
}

func EncodeBytesTrailer(expectedDigestHex string) ([]byte, error) {
	digest, err := hex.DecodeString(expectedDigestHex)
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("trailer digest must be 32-byte hex")
	}
	return digest, nil
}

func DeterministicChunk(seed, counter uint64) [sha256.Size]byte {
	var input [16]byte
	binary.BigEndian.PutUint64(input[0:], seed)
	binary.BigEndian.PutUint64(input[8:], counter)
	return sha256.Sum256(input[:])
}

func GenerateDeterministicData(totalBytes, seed uint64, write func([]byte) error) error {
	var pending [MaxWriteChunkBytes]byte
	pendingLen := 0
	remaining := totalBytes
	counter := uint64(0)
	flush := func() error {
		if pendingLen == 0 {
			return nil
		}
		if err := write(pending[:pendingLen]); err != nil {
			return err
		}
		pendingLen = 0
		return nil
	}
	for remaining > 0 {
		chunk := DeterministicChunk(seed, counter)
		counter++
		take := chunk[:]
		if uint64(len(take)) >= remaining {
			take = take[:remaining]
		}
		remaining -= uint64(len(take))
		for len(take) > 0 {
			space := MaxWriteChunkBytes - pendingLen
			n := min(space, len(take))
			copy(pending[pendingLen:], take[:n])
			pendingLen += n
			take = take[n:]
			if pendingLen == MaxWriteChunkBytes {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	return flush()
}

func ExpectedDigest(totalBytes, seed uint64) string {
	h := sha256.New()
	remaining := totalBytes
	counter := uint64(0)
	for remaining > 0 {
		chunk := DeterministicChunk(seed, counter)
		counter++
		take := chunk[:]
		if uint64(len(take)) >= remaining {
			take = take[:remaining]
		}
		h.Write(take)
		remaining -= uint64(len(take))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
