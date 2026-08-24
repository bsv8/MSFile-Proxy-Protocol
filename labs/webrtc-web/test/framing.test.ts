import { describe, expect, it } from 'vitest'
import { sha256 } from '@noble/hashes/sha2.js'
import {
  encodeEchoFrame,
  parseEchoFrame,
  chunkForWrite,
  MAX_WRITE_CHUNK_BYTES,
  encodeBytesRequest,
  parseBytesRequest,
  encodeBytesResponseHeader,
  parseBytesResponsePrefix,
  encodeBytesTrailer,
  DeterministicBatcher,
  deterministicDataChunk,
  generateDeterministicData,
  expectedDigest,
  runBytesClient
} from '../src/protocols'
import type { Stream } from '@libp2p/interface'

describe('echo framing', () => {
  const fillRandomish = (bytes: Uint8Array): void => {
    let state = 0x9e3779b9
    for (let i = 0; i < bytes.length; i++) {
      state = (state * 1664525 + 1013904223) >>> 0
      bytes[i] = state & 0xff
    }
  }

  it('roundtrips empty and non-empty payloads', () => {
    for (const size of [0, 1, 16384, 262144]) {
      const payload = new Uint8Array(size)
      fillRandomish(payload)
      const frame = encodeEchoFrame(payload)
      expect(frame.byteLength).toBe(size + 8)
      const parsed = parseEchoFrame(frame)
      expect(parsed).toEqual(payload)
    }
  })

  it('rejects frames with mismatched length headers', () => {
    const frame = encodeEchoFrame(new Uint8Array(16))
    const view = new DataView(frame.buffer)
    view.setBigUint64(0, 999n, false)
    expect(() => parseEchoFrame(frame)).toThrow(/mismatch/)
    expect(() => parseEchoFrame(new Uint8Array(4))).toThrow(/too short/)
  })

  it('rejects frames declaring oversized lengths', () => {
    const frame = encodeEchoFrame(new Uint8Array(16))
    const view = new DataView(frame.buffer)
    view.setBigUint64(0, 64n * 1024n * 1024n + 1n, false)
    expect(() => parseEchoFrame(frame)).toThrow(/out of range/)
  })

  it('chunks writes to at most 16 KiB', () => {
    const payload = new Uint8Array(MAX_WRITE_CHUNK_BYTES * 2 + 7)
    const chunks = chunkForWrite(payload)
    expect(chunks.length).toBe(3)
    for (const chunk of chunks.slice(0, 2)) {
      expect(chunk.byteLength).toBeLessThanOrEqual(MAX_WRITE_CHUNK_BYTES)
    }
    expect(chunks[2]?.byteLength).toBe(7)
  })
})

describe('bytes request/response framing', () => {
  it('roundtrips the fixed 20-byte request', () => {
    const req = { totalBytes: 1073741824n, logicalBlockBytes: 262144, seed: 42n }
    const encoded = encodeBytesRequest(req)
    expect(encoded.byteLength).toBe(20)
    expect(parseBytesRequest(encoded)).toEqual(req)
  })

  it('rejects invalid requests', () => {
    expect(() => parseBytesRequest(new Uint8Array(19))).toThrow(/20 bytes/)
    expect(() => encodeBytesRequest({ totalBytes: 1n, logicalBlockBytes: 0, seed: 1n })).toThrow(/logical block/)
    expect(() => encodeBytesRequest({ totalBytes: 9n * 1024n ** 3n, logicalBlockBytes: 4096, seed: 1n })).toThrow(/range/)
  })

  it('uses an 8-byte response header and a separate 32-byte sha256 trailer', () => {
    const header = encodeBytesResponseHeader(5n)
    expect(header.byteLength).toBe(8)
    const parsed = parseBytesResponsePrefix(header)
    expect(parsed.totalBytes).toBe(5n)

    const trailer = encodeBytesTrailer('ab'.repeat(32))
    expect(trailer.byteLength).toBe(32)

    expect(() => parseBytesResponsePrefix(new Uint8Array(7))).toThrow(/incomplete/)
    expect(() => encodeBytesTrailer('zz')).toThrow(/hex/)
  })
})

describe('deterministic data generator (T04/T06/T07 evidence base)', () => {
  const CROSS_LANGUAGE_FIXTURES: Array<{ total: bigint; seed: bigint; digest: string }> = [
    { total: 0n, seed: 1n, digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { total: 1000n, seed: 77n, digest: '5a7ceb5425bc2beba3e82801f7b63d7527914ae64d927933cc4709dfbbaf6187' },
    { total: 65537n, seed: 42n, digest: 'a942a93d550c97b5182fd5f5bb4b240e5fb88264c8b899170a1dad0f41d55282' },
    { total: 262144n, seed: 7n, digest: '601c25f63b6d90ef44c94b747b60bed311c788e7dcd285966de4532b8c5fbc6e' }
  ]

  it('matches the Go-side committed digest fixtures', () => {
    for (const fx of CROSS_LANGUAGE_FIXTURES) {
      expect(expectedDigest(fx.total, fx.seed)).toBe(fx.digest)
    }
  })

  it('produces sha256(seed_be || counter_be) chunks', () => {
    const input = new Uint8Array(16)
    const view = new DataView(input.buffer)
    view.setBigUint64(0, 7n, false)
    view.setBigUint64(8, 0n, false)
    const expectedChunk = sha256(input)
    expect(deterministicDataChunk(7n, 0n)).toEqual(expectedChunk)
    view.setBigUint64(8, 1n, false)
    expect(deterministicDataChunk(7n, 1n)).toEqual(sha256(input.slice()))
  })

  it('streams exactly total bytes across chunk boundaries', async () => {
    for (const total of [0n, 31n, 32n, 33n, 1000n]) {
      let collected = new Uint8Array(0)
      for await (const chunk of generateDeterministicData(total, 123n)) {
        const merged = new Uint8Array(collected.byteLength + chunk.byteLength)
        merged.set(collected)
        merged.set(chunk, collected.byteLength)
        collected = merged
      }
      expect(BigInt(collected.byteLength)).toBe(total)
    }
  })

  it('batches generation into writes of at most 16 KiB (T14 memory bound)', async () => {
    let maxBatch = 0
    let total = 0
    for await (const batch of generateDeterministicData(100000n, 9n)) {
      maxBatch = Math.max(maxBatch, batch.byteLength)
      total += batch.byteLength
    }
    expect(total).toBe(100000)
    expect(maxBatch).toBeLessThanOrEqual(MAX_WRITE_CHUNK_BYTES)
    if (total > MAX_WRITE_CHUNK_BYTES) {
      expect(maxBatch).toBe(MAX_WRITE_CHUNK_BYTES)
    }
  })

  it('batcher digest matches the committed fixtures without an extra pass over stored data', () => {
    for (const fx of CROSS_LANGUAGE_FIXTURES) {
      const batcher = new DeterministicBatcher(fx.total, fx.seed)
      let produced = 0n
      for (;;) {
        const batch = batcher.nextBatch()
        if (batch == null) break
        produced += BigInt(batch.byteLength)
      }
      expect(produced).toBe(fx.total)
      expect(batcher.digestHex()).toBe(fx.digest)
    }
  })

  it('is stable across calls and sensitive to seed/counter', () => {
    expect(expectedDigest(64n, 1n)).toBe(expectedDigest(64n, 1n))
    expect(expectedDigest(64n, 1n)).not.toBe(expectedDigest(64n, 2n))
    expect(expectedDigest(63n, 1n)).not.toBe(expectedDigest(64n, 1n))
  })
})

interface FakeStreamOptions {
  chunks: Uint8Array[]
}

function fakeServerStream(options: FakeStreamOptions): Stream {
  const sent: Uint8Array[] = []
  const stream = {
    writableNeedsDrain: false,
    send(data: Uint8Array): boolean {
      sent.push(data.slice())
      return true
    },
    async close(): Promise<void> {},
    addEventListener(): void {},
    removeEventListener(): void {},
    abort(): void {},
    async *[Symbol.asyncIterator](): AsyncGenerator<Uint8Array> {
      for (const c of options.chunks) {
        yield c
      }
      void sent
    }
  }
  return stream as unknown as Stream
}

function concatAll(chunks: Uint8Array[]): Uint8Array {
  let n = 0
  for (const c of chunks) n += c.byteLength
  const out = new Uint8Array(n)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.byteLength
  }
  return out
}

describe('runBytesClient tolerates fragmented reads (issue 6)', () => {
  function buildResponse(total: bigint, seed: bigint): Uint8Array[] {
    const parts: Uint8Array[] = [encodeBytesResponseHeader(total)]
    const batcher = new DeterministicBatcher(total, seed)
    for (;;) {
      const batch = batcher.nextBatch()
      if (batch == null) break
      parts.push(batch)
    }
    parts.push(encodeBytesTrailer(expectedDigest(total, seed)))
    return parts
  }

  function fragment(parts: Uint8Array[], sizes: number[]): Uint8Array[] {
    const flat = concatAll(parts)
    expect(sizes.reduce((a, b) => a + b, 0)).toBe(flat.byteLength)
    const out: Uint8Array[] = []
    let offset = 0
    for (const size of sizes) {
      out.push(flat.subarray(offset, offset + size))
      offset += size
    }
    return out
  }

  const cases: Array<{ name: string; total: bigint; seed: bigint; split: number[] }> = [
    { name: 'single chunk', total: 1000n, seed: 77n, split: [8 + 1000 + 32] },
    { name: 'header split into 1-byte reads', total: 1000n, seed: 77n, split: [1, 7, 39, 500, 493] },
    { name: '7 then 7 byte fragments', total: 65537n, seed: 42n, split: [7, 7, 26, 30000, 30000, 5537] },
    { name: '39-byte first read straddles header and payload', total: 262144n, seed: 7n, split: [39, 1000, 261145] }
  ]

  for (const tc of cases) {
    it(`passes: ${tc.name}`, async () => {
      const stream = fakeServerStream({ chunks: fragment(buildResponse(tc.total, tc.seed), tc.split) })
      const result = await runBytesClient(stream, { totalBytes: tc.total, logicalBlockBytes: 4096, seed: tc.seed })
      expect(result.lengthMatches).toBe(true)
      expect(result.digestMatches).toBe(true)
      expect(result.trailerDigestHex).toBe(expectedDigest(tc.total, tc.seed))
      expect(result.totalBytesReceived).toBe(Number(tc.total))
    })
  }

  it('fails validation when the response is truncated before the full trailer', async () => {
    const parts = buildResponse(1000n, 77n)
    const truncated = concatAll(parts).subarray(0, 8 + 1000 + 16)
    const stream = fakeServerStream({ chunks: [truncated] })
    const result = await runBytesClient(stream, { totalBytes: 1000n, logicalBlockBytes: 4096, seed: 77n })
    expect(result.lengthMatches).toBe(false)
    expect(result.digestMatches).toBe(false)
    expect(result.totalBytesReceived).toBeLessThan(1000)
  })

  it('rejects a server announcing a different total than requested', async () => {
    const parts = buildResponse(2000n, 77n)
    const stream = fakeServerStream({ chunks: [concatAll(parts)] })
    await expect(
      runBytesClient(stream, { totalBytes: 1000n, logicalBlockBytes: 4096, seed: 77n })
    ).rejects.toThrow(/announced 2000/)
  })
})
