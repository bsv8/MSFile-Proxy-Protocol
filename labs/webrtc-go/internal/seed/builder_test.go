package seed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// lcgBytes 用固定种子的 LCG 生成 n 字节确定性伪随机数据，
// 既避免全零/全同字符这种“退化输入”，又保证测试可重复。
func lcgBytes(n int) []byte {
	out := make([]byte, n)
	var x uint32 = 0x12345678
	for i := range out {
		x = x*1664525 + 1013904223
		out[i] = byte(x >> 24)
	}
	return out
}

// wireV1Expect 按 Wire V1 公式独立重算期望值：
// 逐块 SHA-256 -> 拼接为 seed_bytes -> 再做一次 SHA-256 得到 seed_hash。
// 这是与被测实现互为印证的“手工参照实现”。
func wireV1Expect(src []byte) (seed []byte, seedHash [32]byte, blockHashes [][32]byte) {
	// 拼接必须用字节缓冲；hash.Hash 的 Sum 只会给出固定 32 字节摘要。
	var concat bytes.Buffer
	for off := 0; off < len(src); off += BlockSizeBytes {
		end := off + BlockSizeBytes
		if end > len(src) {
			end = len(src)
		}
		d := sha256.Sum256(src[off:end])
		blockHashes = append(blockHashes, d)
		concat.Write(d[:])
	}
	seed = append([]byte(nil), concat.Bytes()...)
	seedHash = sha256.Sum256(seed)
	return seed, seedHash, blockHashes
}

// TestBuildEmptyFile 校验空文件这一合法边界：Seed 为空、无块、
// SeedHash 等于对空输入做的 SHA-256（即著名的 e3b0c4... 开头摘要）。
func TestBuildEmptyFile(t *testing.T) {
	res, err := Build(bytes.NewReader(nil), "empty.txt")
	if err != nil {
		t.Fatalf("Build(空文件) 不应报错: %v", err)
	}
	if res.SourceSize != 0 {
		t.Errorf("SourceSize = %d, 期望 0", res.SourceSize)
	}
	if len(res.Seed) != 0 {
		t.Errorf("len(Seed) = %d, 期望 0", len(res.Seed))
	}
	if len(res.Blocks) != 0 {
		t.Errorf("len(Blocks) = %d, 期望空切片", len(res.Blocks))
	}
	want := sha256.Sum256([]byte{})
	if res.SeedHash != want {
		t.Errorf("SeedHash = %x, 期望空输入摘要 %x", res.SeedHash, want)
	}
	// 额外对照公开已知的空串 SHA-256 十六进制值，防止实现悄悄改算法。
	const wantHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(res.SeedHash[:]); got != wantHex {
		t.Errorf("SeedHash hex = %s, 期望 %s", got, wantHex)
	}
}

// TestBuildSingleFullBlock 校验恰好一个完整 256 KiB 块的文件：
// 块元数据、块哈希、Seed 拼接与 SeedHash 都要逐字节吻合。
func TestBuildSingleFullBlock(t *testing.T) {
	src := bytes.Repeat([]byte{'A'}, BlockSizeBytes) // 262144 个 'A'
	res, err := Build(bytes.NewReader(src), "block.bin")
	if err != nil {
		t.Fatalf("Build 不应报错: %v", err)
	}
	if res.SourceSize != int64(BlockSizeBytes) {
		t.Errorf("SourceSize = %d, 期望 %d", res.SourceSize, BlockSizeBytes)
	}
	if len(res.Blocks) != 1 {
		t.Fatalf("len(Blocks) = %d, 期望 1", len(res.Blocks))
	}
	b := res.Blocks[0]
	if b.Index != 0 {
		t.Errorf("blocks[0].Index = %d, 期望 0", b.Index)
	}
	if b.Offset != 0 {
		t.Errorf("blocks[0].Offset = %d, 期望 0", b.Offset)
	}
	if b.Length != BlockSizeBytes {
		t.Errorf("blocks[0].Length = %d, 期望 %d", b.Length, BlockSizeBytes)
	}
	wantBlock := sha256.Sum256(src)
	if b.Hash != wantBlock {
		t.Errorf("blocks[0].Hash = %x, 期望 %x", b.Hash, wantBlock)
	}
	// Seed 应当就是该唯一块哈希的 32 字节拼接。
	if !bytes.Equal(res.Seed, wantBlock[:]) {
		t.Errorf("Seed = %x, 期望单块哈希拼接 %x", res.Seed, wantBlock)
	}
	wantSeedHash := sha256.Sum256(res.Seed)
	if res.SeedHash != wantSeedHash {
		t.Errorf("SeedHash = %x, 期望 sha256(Seed) = %x", res.SeedHash, wantSeedHash)
	}
}

// TestBuildMultiBlocksWithShortTail 校验“多个完整块 + 最后一个短块”的典型形态：
// 600000 字节 = 2 个完整块 + 75652 字节短块；逐块独立核对 SHA-256 与偏移。
func TestBuildMultiBlocksWithShortTail(t *testing.T) {
	const total = 600000 // 262144*2 + 75652
	src := lcgBytes(total)
	res, err := Build(bytes.NewReader(src), "multi.dat")
	if err != nil {
		t.Fatalf("Build 不应报错: %v", err)
	}
	if res.SourceSize != total {
		t.Errorf("SourceSize = %d, 期望 %d", res.SourceSize, total)
	}
	const wantBlocks = 3
	if len(res.Blocks) != wantBlocks {
		t.Fatalf("len(Blocks) = %d, 期望 %d", len(res.Blocks), wantBlocks)
	}
	last := res.Blocks[len(res.Blocks)-1]
	if last.Offset != 2*BlockSizeBytes {
		t.Errorf("最后一块 Offset = %d, 期望 %d", last.Offset, 2*BlockSizeBytes)
	}
	if wantLen := total - 2*BlockSizeBytes; last.Length != wantLen {
		t.Errorf("最后一块 Length = %d, 期望 %d（短块）", last.Length, wantLen)
	}
	// 逐块独立校验：Index、Offset、Length、SHA-256 全部对上。
	for i, b := range res.Blocks {
		if b.Index != int64(i) {
			t.Errorf("blocks[%d].Index = %d, 期望 %d", i, b.Index, i)
		}
		if wantOff := int64(i) * BlockSizeBytes; b.Offset != wantOff {
			t.Errorf("blocks[%d].Offset = %d, 期望 %d", i, b.Offset, wantOff)
		}
		chunk := src[i*BlockSizeBytes : min((i+1)*BlockSizeBytes, total)]
		if b.Length != len(chunk) {
			t.Errorf("blocks[%d].Length = %d, 期望 %d", i, b.Length, len(chunk))
		}
		want := sha256.Sum256(chunk)
		if b.Hash != want {
			t.Errorf("blocks[%d].Hash = %x, 期望 %x", i, b.Hash, want)
		}
	}
	// Seed 是全部块哈希的顺序拼接，SeedHash 再对拼接结果求一次哈希。
	var concat []byte
	for _, b := range res.Blocks {
		concat = append(concat, b.Hash[:]...)
	}
	if !bytes.Equal(res.Seed, concat) {
		t.Error("Seed 与各块哈希顺序拼接不一致")
	}
	wantSeedHash := sha256.Sum256(concat)
	if res.SeedHash != wantSeedHash {
		t.Errorf("SeedHash = %x, 期望 %x", res.SeedHash, wantSeedHash)
	}
}

// TestBuildFixedVectorTwoBlocks 构造大于等于两块的固定向量，
// 用 Wire V1 公式手工重算期望值并逐字节比对（含随机化内容防退化）。
func TestBuildFixedVectorTwoBlocks(t *testing.T) {
	total := BlockSizeBytes*2 + 131072 // 2.5 块规模
	src := lcgBytes(total)
	wantSeed, wantSeedHash, wantBlockHashes := wireV1Expect(src)

	res, err := Build(bytes.NewReader(src), "fixed.vec")
	if err != nil {
		t.Fatalf("Build 不应报错: %v", err)
	}
	if !bytes.Equal(res.Seed, wantSeed) {
		t.Errorf("Seed 与手工公式不一致:\n got=%x\nwant=%x", res.Seed, wantSeed)
	}
	if res.SeedHash != wantSeedHash {
		t.Errorf("SeedHash = %x, 期望 %x", res.SeedHash, wantSeedHash)
	}
	if len(res.Blocks) != len(wantBlockHashes) {
		t.Fatalf("len(Blocks) = %d, 期望 %d", len(res.Blocks), len(wantBlockHashes))
	}
	for i, b := range res.Blocks {
		if b.Hash != wantBlockHashes[i] {
			t.Errorf("blocks[%d].Hash = %x, 期望 %x", i, b.Hash, wantBlockHashes[i])
		}
	}
}

// TestSafeFilename 表驱动校验任意输入收敛成合法 basename 的行为。
func TestSafeFilename(t *testing.T) {
	cases := []struct {
		name string // 子测试名
		in   string // 输入文件名
		want string // 期望输出
	}{
		// 分隔符行为按实现：先把 \\ 归一成 /，再取 basename。
		{"混合分隔符收敛为basename", "a/b\\c.txt", "c.txt"},
		{"纯反斜杠路径", "dir\\file.tar.gz", "file.tar.gz"},
		{"删除控制字符含NUL和TAB", "a\x00b\tc\x1f\x7f.txt", "abc.txt"},
		{"首尾空白被裁掉", "  spaced.txt\t", "spaced.txt"},
		{"单个点是非法名", ".", ""},
		{"双点是非法名", "..", ""},
		{"根目录斜杠是非法名", "/", ""},
		{"多个斜杠同样归空", "///", ""},
		{"空字符串归空", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeFilename(tc.in)
			if got != tc.want {
				t.Errorf("SafeFilename(%q) = %q, 期望 %q", tc.in, got, tc.want)
			}
		})
	}

	// 超 255 UTF-8 字节必须截断且截断结果仍是合法 UTF-8。
	t.Run("超长UTF8截断", func(t *testing.T) {
		long := strings.Repeat("汉", 100) // 每个 '汉' 占 3 字节，共 300 字节
		got := SafeFilename(long)
		if len(got) > 255 {
			t.Fatalf("截断后仍有 %d 字节, 超过 255 上限", len(got))
		}
		if !utf8.ValidString(got) {
			t.Fatal("截断结果不是合法 UTF-8")
		}
		if want := strings.Repeat("汉", 85); got != want { // 85*3 = 255 字节整
			t.Errorf("截断结果长度 %d 字节, 期望保留前 85 个汉字 (255 字节)", len(got))
		}
	})
}

// TestDetectMediaType 校验扩展名优先、嗅探兜底的 MIME 推断。
func TestDetectMediaType(t *testing.T) {
	pngMagic := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0}, 64)...)
	cases := []struct {
		name     string
		filename string
		first    []byte // 首块内容（用于嗅探）
		want     string
	}{
		// .txt 走 Go 内置 mime 表，跨平台稳定；参数部分必须剥掉。
		{"文本文件走扩展名", "notes.txt", []byte("plain text"), "text/plain"},
		{"未知扩展名嗅探出PNG", "photo.unknownext123", pngMagic, "image/png"},
		{"未知扩展名二进制内容兜底octet-stream", "blob.unknownext123", []byte{0x00, 0x01, 0x02, 0xFE}, "application/octet-stream"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := detectMediaType(tc.filename, tc.first)
			if got != tc.want {
				t.Errorf("detectMediaType(%q) = %q, 期望 %q", tc.filename, got, tc.want)
			}
			if strings.Contains(got, ";") {
				t.Errorf("media type %q 不应携带参数部分", got)
			}
		})
	}
}

// TestCleanMediaType 校验参数剥离与 wire 约束回退逻辑。
func TestCleanMediaType(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"剥离charset参数", "text/html; charset=utf-8", "text/html"},
		{"无参数原样通过", "application/json", "application/json"},
		{"空串回退octet-stream", "", "application/octet-stream"},
		{"超长值回退octet-stream", strings.Repeat("a/b/", 100), "application/octet-stream"}, // 400 字节 > 255
		{"含控制字符回退octet-stream", "bad\x01type", "application/octet-stream"},
		{"解析失败时按分号截断", "foo/bar;;weird", "foo/bar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cleanMediaType(tc.in)
			if got != tc.want {
				t.Errorf("cleanMediaType(%q) = %q, 期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestBuildMediaTypeConstraints 从 Build 出口整体校验 media type 的 wire 约束：
// 无参数、不超过 255 字节、全部为可打印 ASCII。
func TestBuildMediaTypeConstraints(t *testing.T) {
	res, err := Build(bytes.NewReader(lcgBytes(1024)), "doc.txt")
	if err != nil {
		t.Fatalf("Build 不应报错: %v", err)
	}
	if res.MediaType == "" {
		t.Fatal("MediaType 不应为空")
	}
	if strings.Contains(res.MediaType, ";") {
		t.Errorf("MediaType %q 不应包含参数部分", res.MediaType)
	}
	if len(res.MediaType) > 255 {
		t.Errorf("MediaType 长度 %d 超过 255 字节上限", len(res.MediaType))
	}
	for i := 0; i < len(res.MediaType); i++ {
		if c := res.MediaType[i]; c < 0x20 || c > 0x7e {
			t.Fatalf("MediaType 含非打印 ASCII 字节 0x%02x（位置 %d）", c, i)
		}
	}
	if res.RecommendedFilename != "doc.txt" {
		t.Errorf("RecommendedFilename = %q, 期望 %q", res.RecommendedFilename, "doc.txt")
	}
}

// fakeHugeReader 以极小真实内存模拟超过 128 GiB 的超大源文件。
//
// 为什么不能“慢慢喂”：Build 的 sourceSize 只由每次 Read 上报的 n 累加而来，
// 若要靠真实字节累加到 128 GiB 需要做 52 万次块哈希，耗时以分钟计；
// 因此必须让某次 Read 上报一个超长 n。
//
// 为什么只允许两次调用：
//   - 第 1 次必须诚实返回 len(p)：index==0 时 Build 会用 buf[:n] 做媒体嗅探，
//     超长 n 会在这里越界 panic；
//   - 第 2 次上报“刚好越过红线 1 字节”的 n：Build 在使用 buf[:n] 之前
//     先做 sourceSize 校验并返回 ErrTooLarge，因此不会越界。
//     注意任何“未导致越线”的超长 n 都会流到 sha256.Sum256(buf[:n]) 而 panic，
//     所以不存在分多步谎报的空间。
//
// 本机 int 为 64 位，MaxSourceBytes-len(p)+1 ≈ 1.37e11 可安全转换；
// 全程仅分配一个 256 KiB 块缓冲，内存有界、瞬时完成。
type fakeHugeReader struct {
	honestLeft int   // 剩余的诚实读取次数
	reported   int64 // 已向 Build 上报的累计字节数
	readCalls  int   // 真实调用次数统计，用于佐证工作量有界
}

// Read 第一次把缓冲整体填满，之后单次上报足以触发尺寸红线的字节数。
func (r *fakeHugeReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0xAB
	}
	r.readCalls++
	if r.honestLeft > 0 {
		r.honestLeft--
		r.reported += int64(len(p))
		return len(p), nil
	}
	n := MaxSourceBytes - r.reported + 1
	r.reported += n
	return int(n), nil
}

// TestBuildOversizedSourceReturnsErrTooLarge 是超大文件保护的关键测试：
// 不真实分配 128 GiB，通过 fakeHugeReader 让 Build 的尺寸守卫生效，
// 断言最终错误可用 errors.Is 匹配 ErrTooLarge，且全程读取次数有界。
func TestBuildOversizedSourceReturnsErrTooLarge(t *testing.T) {
	r := &fakeHugeReader{honestLeft: 1}
	res, err := Build(r, "huge.bin")
	if res != nil {
		t.Fatalf("越线时 Result 应为 nil，却得到 SourceSize=%d", res.SourceSize)
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("期望 ErrTooLarge, 实际: %v", err)
	}
	// 佐证内存与计算有界：真实调用次数应远小于越线所需的 524288 个块。
	if r.readCalls > 10 {
		t.Errorf("fake reader 真实读取 %d 次，超出预期上界 10，说明策略失效", r.readCalls)
	}
}

// failingReader 在提供 after 次成功读取后返回自定义业务错误，
// 用于验证 Build 会把底层读错误原样透传（errors.Is 可匹配）。
type failingReader struct {
	after int
	err   error
	n     int
}

func (r *failingReader) Read(p []byte) (int, error) {
	if r.n >= r.after {
		return 0, r.err
	}
	r.n++
	for i := range p {
		p[i] = 'B'
	}
	return len(p), nil
}

// TestBuildPropagatesCustomReadError 校验中途的自定义读错误不会被吞掉或误判成 EOF。
func TestBuildPropagatesCustomReadError(t *testing.T) {
	myErr := errors.New("模拟磁盘故障")
	_, err := Build(&failingReader{after: 1, err: myErr}, "badluck.bin")
	if !errors.Is(err, myErr) {
		t.Fatalf("期望透传自定义错误, 实际: %v", err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("自定义错误不应被当成 EOF 处理: %v", err)
	}
}
