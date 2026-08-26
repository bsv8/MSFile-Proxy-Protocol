// Package seed 负责 MasterSeed V1 的流式计算与磁盘存放。
//
// 算法严格沿用 Wire V1：
//
//	BLOCK_SIZE_BYTES = 262144
//	block_hash[i]    = SHA-256(source_block[i])
//	seed_bytes       = block_hash[0] || ... || block_hash[n-1]
//	seed_hash        = SHA-256(seed_bytes)
//
// 空文件合法：seed 为 0 字节，seed_hash 是 SHA-256 空输入。
// Builder 不写 SQLite、不发布任何状态；提交由 library 协调器在 stat C 通过后完成。
package seed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// 协议冻结常量。
const (
	BlockSizeBytes = 262144              // 256 KiB
	MaxSeedBytes   = 16777216            // 16 MiB = 65536 块
	MaxSourceBytes = int64(137438953472) // 128 GiB = 16 MiB Seed 推导上限
)

// Block 是一个源文件块的哈希映射。
type Block struct {
	Index  int64    // 从 0 开始的块序号
	Hash   [32]byte // SHA-256(source_block)
	Offset int64    // 在原文件中的字节偏移 = Index * BlockSizeBytes
	Length int      // 1..262144；最后一块可以更短
}

// Result 是 Builder 的完整输出。
type Result struct {
	SeedHash            [32]byte // SHA-256(seed_bytes)
	Seed                []byte   // 原始 MasterSeed 字节（块哈希拼接）
	SourceSize          int64    // 原文件字节数
	Blocks              []Block  // 全部块映射；空文件为空切片
	RecommendedFilename string   // 建议文件名（basename）
	MediaType           string   // MIME 类型
}

var (
	// ErrTooLarge 表示源文件超过 MSFile V1 最大尺寸 128 GiB。
	ErrTooLarge = errors.New("文件超过 MSFile V1 最大源文件尺寸 128 GiB")
)

// Build 流式读取 r 并计算 Seed。
// 内存占用有界：任意时刻只保留一个 256 KiB 块缓冲和最多 16 MiB 的 Seed 字节，
// 不把整个源文件读进内存。
func Build(r io.Reader, filename string) (*Result, error) {
	var seedBuf bytes.Buffer
	blocks := make([]Block, 0, 64)
	buf := make([]byte, BlockSizeBytes)
	var sourceSize int64
	var mediaType string

	for index := int64(0); ; index++ {
		n, readErr := io.ReadFull(r, buf)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("读取原文件失败: %w", readErr)
		}
		if n == 0 {
			break // 正常 EOF；空文件在 index==0 时直接结束
		}
		sourceSize += int64(n)
		if sourceSize > MaxSourceBytes {
			return nil, ErrTooLarge
		}
		if index == 0 {
			mediaType = detectMediaType(filename, buf[:n])
		}
		digest := sha256.Sum256(buf[:n])
		if _, err := seedBuf.Write(digest[:]); err != nil {
			return nil, err
		}
		if seedBuf.Len() > MaxSeedBytes {
			return nil, ErrTooLarge
		}
		blocks = append(blocks, Block{Index: index, Hash: digest, Offset: index * BlockSizeBytes, Length: n})
		if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
	}
	seedHash := sha256.Sum256(seedBuf.Bytes())
	return &Result{
		SeedHash:            seedHash,
		Seed:                seedBuf.Bytes(),
		SourceSize:          sourceSize,
		Blocks:              blocks,
		RecommendedFilename: SafeFilename(filename),
		MediaType:           mediaType,
	}, nil
}

// SafeFilename 把任意输入收敛成符合 Wire V1 约束的 basename：
// 单个 basename、不含分隔符/NUL/控制字符、不是 . 或 ..、UTF-8 ≤ 255 字节。
func SafeFilename(name string) string {
	name = filepath.Base(strings.ReplaceAll(strings.TrimSpace(name), "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	if name == "." || name == ".." || name == "/" {
		return ""
	}
	for len([]byte(name)) > 255 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name
}

// detectMediaType 优先用扩展名推断 MIME；失败时嗅探首块内容。
func detectMediaType(filename string, firstBlock []byte) string {
	if value := mime.TypeByExtension(filepath.Ext(filename)); value != "" {
		if clean := cleanMediaType(value); clean != "" {
			return clean
		}
	}
	sniffed := http.DetectContentType(firstBlock)
	return cleanMediaType(sniffed)
}

// cleanMediaType 去掉 mime 包可能附加的参数部分，并校验 wire 约束：
// 可打印 ASCII、≤255 字节。不合法时回退 application/octet-stream。
func cleanMediaType(value string) string {
	if base, _, err := mime.ParseMediaType(value); err == nil {
		value = base
	} else if i := strings.IndexByte(value, ';'); i >= 0 {
		value = strings.TrimSpace(value[:i])
	}
	if value == "" || len(value) > 255 {
		return "application/octet-stream"
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return "application/octet-stream"
		}
	}
	return value
}

// HashHex 返回 64 位小写 hex 形式的 Seed 哈希。
func (r *Result) HashHex() string { return hex.EncodeToString(r.SeedHash[:]) }
