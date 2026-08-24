import type { Connection, Stream } from '@libp2p/interface'
import type { Uint8ArrayList } from 'uint8arraylist'
import { sha256 } from '@noble/hashes/sha2.js'
import { IncrementalSha256, toHex } from './stats'

export const PROTOCOL_IDENTITY = '/msfile-lab/identity/1.0.0'
export const PROTOCOL_ECHO = '/msfile-lab/echo/1.0.0'
export const PROTOCOL_BYTES = '/msfile-lab/bytes/1.0.0'

export const MAX_WRITE_CHUNK_BYTES = 16384
export const DEFAULT_LOGICAL_BLOCK_BYTES = 262144
export const ECHO_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
export const BYTES_MAX_TOTAL = 8n * 1024n * 1024n * 1024n

export const BYTES_RESPONSE_HEADER_LEN = 8
export const BYTES_TRAILER_LEN = 32
const DATA_CHUNK_SIZE = 32

export interface BytesRequest {
  totalBytes: bigint
  logicalBlockBytes: number
  seed: bigint
}

export interface IdentityDiagnostics {
  remote_peer_id: string
  remote_public_key_hex: string
  local_peer_id: string
  local_public_key_hex: string
  direction: string
  direct: boolean
  limited: boolean
  transport: string
}

export function encodeEchoFrame(payload: Uint8Array): Uint8Array {
  if (payload.byteLength > ECHO_MAX_PAYLOAD_BYTES) {
    throw new Error(`echo payload too large: ${payload.byteLength} > ${ECHO_MAX_PAYLOAD_BYTES}`)
  }
  const out = new Uint8Array(8 + payload.byteLength)
  const view = new DataView(out.buffer)
  view.setBigUint64(0, BigInt(payload.byteLength), false)
  out.set(payload, 8)
  return out
}

export function parseEchoFrame(data: Uint8Array): Uint8Array {
  if (data.byteLength < 8) {
    throw new Error(`echo frame too short: ${data.byteLength}`)
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const len = view.getBigUint64(0, false)
  if (len > BigInt(ECHO_MAX_PAYLOAD_BYTES)) {
    throw new Error(`echo frame length out of range: ${len}`)
  }
  if (data.byteLength - 8 !== Number(len)) {
    throw new Error(`echo frame length mismatch: header=${len} body=${data.byteLength - 8}`)
  }
  return data.subarray(8)
}

export function chunkForWrite(payload: Uint8Array, maxChunk = MAX_WRITE_CHUNK_BYTES): Uint8Array[] {
  const chunks: Uint8Array[] = []
  for (let offset = 0; offset < payload.byteLength; offset += maxChunk) {
    chunks.push(payload.subarray(offset, Math.min(offset + maxChunk, payload.byteLength)))
  }
  return chunks.length > 0 ? chunks : [new Uint8Array(0)]
}

export function encodeBytesRequest(req: BytesRequest): Uint8Array {
  if (!Number.isInteger(req.logicalBlockBytes) || req.logicalBlockBytes <= 0 || req.logicalBlockBytes > 0xffffffff) {
    throw new Error(`invalid logical block size: ${req.logicalBlockBytes}`)
  }
  if (req.totalBytes < 0n || req.totalBytes > BYTES_MAX_TOTAL) {
    throw new Error(`total bytes out of lab range: ${req.totalBytes}`)
  }
  const out = new Uint8Array(20)
  const view = new DataView(out.buffer)
  view.setBigUint64(0, req.totalBytes, false)
  view.setUint32(8, req.logicalBlockBytes, false)
  view.setBigUint64(12, req.seed, false)
  return out
}

export function parseBytesRequest(data: Uint8Array): BytesRequest {
  if (data.byteLength !== 20) {
    throw new Error(`bytes request must be exactly 20 bytes, got ${data.byteLength}`)
  }
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const totalBytes = view.getBigUint64(0, false)
  const logicalBlockBytes = view.getUint32(8, false)
  const seed = view.getBigUint64(12, false)
  if (logicalBlockBytes === 0) {
    throw new Error('logical block size must not be zero')
  }
  if (totalBytes > BYTES_MAX_TOTAL) {
    throw new Error(`total bytes out of lab range: ${totalBytes}`)
  }
  return { totalBytes, logicalBlockBytes, seed }
}

export function encodeBytesResponseHeader(totalBytes: bigint): Uint8Array {
  const out = new Uint8Array(BYTES_RESPONSE_HEADER_LEN)
  new DataView(out.buffer).setBigUint64(0, totalBytes, false)
  return out
}

export function parseBytesResponsePrefix(data: Uint8Array): { totalBytes: bigint; consumed: number } {
  if (data.byteLength < BYTES_RESPONSE_HEADER_LEN) {
    throw new Error(`bytes response prefix incomplete: got ${data.byteLength}, want ${BYTES_RESPONSE_HEADER_LEN}`)
  }
  return {
    totalBytes: new DataView(data.buffer, data.byteOffset, data.byteLength).getBigUint64(0, false),
    consumed: BYTES_RESPONSE_HEADER_LEN
  }
}

export function encodeBytesTrailer(digestHex: string): Uint8Array {
  const digest = fromHexStrict(digestHex)
  if (digest.length !== BYTES_TRAILER_LEN) {
    throw new Error('trailer digest must be 32-byte hex')
  }
  return digest.slice()
}

function fromHexStrict(hex: string): Uint8Array {
  if (/[^0-9a-f]/.test(hex) || hex.length % 2 !== 0) {
    throw new Error('invalid hex')
  }
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export function deterministicDataChunk(seed: bigint, counter: bigint): Uint8Array {
  const input = new Uint8Array(16)
  const view = new DataView(input.buffer)
  view.setBigUint64(0, seed, false)
  view.setBigUint64(8, counter, false)
  return sha256(input)
}

export class DeterministicBatcher {
  private readonly buffer = new Uint8Array(MAX_WRITE_CHUNK_BYTES)
  private filled = 0
  private counter = 0n
  private remaining: bigint
  readonly hash = sha256.create()

  constructor(private readonly totalBytes: bigint, private readonly seed: bigint) {
    this.remaining = totalBytes
  }

  get producedBytes(): bigint {
    return this.totalBytes - this.remaining
  }

  nextBatch(): Uint8Array | undefined {
    if (this.remaining === 0n) {
      return this.flushFinal()
    }
    while (this.filled < MAX_WRITE_CHUNK_BYTES && this.remaining > 0n) {
      const chunk = deterministicDataChunk(this.seed, this.counter)
      this.counter += 1n
      const take = chunk.length >= this.remaining ? Number(this.remaining) : chunk.length
      this.hash.update(chunk.subarray(0, take))
      this.buffer.set(chunk.subarray(0, take), this.filled)
      this.filled += take
      this.remaining -= BigInt(take)
    }
    const out = this.buffer.slice(0, this.filled)
    this.filled = 0
    return out
  }

  private flushFinal(): Uint8Array | undefined {
    if (this.filled === 0) {
      return undefined
    }
    const out = this.buffer.slice(0, this.filled)
    this.filled = 0
    return out
  }

  digestHex(): string {
    return toHex(this.hash.digest().slice())
  }
}

export async function* generateDeterministicData(totalBytes: bigint, seed: bigint): AsyncGenerator<Uint8Array> {
  const batcher = new DeterministicBatcher(totalBytes, seed)
  for (;;) {
    const batch = batcher.nextBatch()
    if (batch == null) {
      return
    }
    yield batch
  }
}

export function expectedDigest(totalBytes: bigint, seed: bigint): string {
  const batcher = new DeterministicBatcher(totalBytes, seed)
  let digest = ''
  for (;;) {
    const batch = batcher.nextBatch()
    if (batch == null) {
      digest = batcher.digestHex()
      break
    }
  }
  return digest
}

export interface ConnInfo {
  remotePeerId: string
  remotePublicKeyHex: string | undefined
  localPeerId: string
  localPublicKeyHex: string | undefined
  direction: string
  direct: boolean
  limited: boolean
  transport: string
}

export interface LabStreamContext {
  stream: Stream
  info: ConnInfo
}

function flatten(buf: Uint8Array | Uint8ArrayList): Uint8Array {
  return buf instanceof Uint8Array ? buf : buf.subarray()
}

export async function sendAll(stream: Stream, chunks: Uint8Array[], signal?: AbortSignal): Promise<void> {
  for (const chunk of chunks) {
    await sendOne(stream, chunk, signal)
  }
}

async function sendOne(stream: Stream, chunk: Uint8Array, signal?: AbortSignal): Promise<void> {
  if (!stream.writableNeedsDrain && stream.send(chunk)) {
    return
  }
  while (stream.writableNeedsDrain) {
    if (signal?.aborted === true) {
      throw new Error('aborted while waiting for stream drain')
    }
    await waitForDrain(stream, signal)
  }
  stream.send(chunk)
  if (stream.writableNeedsDrain) {
    await waitForDrain(stream, signal)
  }
}

function waitForDrain(stream: Stream, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false
    const done = (): void => {
      if (settled) return
      settled = true
      cleanup()
      resolve()
    }
    const fail = (): void => {
      if (settled) return
      settled = true
      cleanup()
      reject(new Error('stream closed while waiting for drain'))
    }
    const onAbort = (): void => fail()
    const cleanup = (): void => {
      stream.removeEventListener('drain', done)
      stream.removeEventListener('close', fail)
      signal?.removeEventListener('abort', onAbort)
    }
    stream.addEventListener('drain', done)
    stream.addEventListener('close', fail)
    signal?.addEventListener('abort', onAbort)
  })
}

export async function readAllUntilEof(stream: Stream, maxBytes: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let total = 0
  for await (const buf of stream) {
    const flat = flatten(buf).slice()
    total += flat.byteLength
    if (total > maxBytes) {
      throw new Error(`stream exceeded ${maxBytes} byte limit`)
    }
    chunks.push(flat)
  }
  let merged = 0
  for (const c of chunks) {
    merged += c.byteLength
  }
  const out = new Uint8Array(merged)
  let offset = 0
  for (const c of chunks) {
    out.set(c, offset)
    offset += c.byteLength
  }
  return out
}

export interface ByteSource {
  batches: AsyncGenerator<Uint8Array>
  digestHex: () => Promise<string>
  close: () => void
}

export interface ByteSourceHooks {
  onProduced?: (bytes: number) => void
}

let sharedWorker: Worker | undefined

export function createByteSource(totalBytes: bigint, seed: bigint, hooks?: ByteSourceHooks): ByteSource {
  if (typeof Worker !== 'undefined') {
    try {
      return createWorkerByteSource(totalBytes, seed, hooks)
    } catch {
      sharedWorker?.terminate()
      sharedWorker = undefined
    }
  }
  return createInlineByteSource(totalBytes, seed, hooks)
}

function createInlineByteSource(totalBytes: bigint, seed: bigint, hooks?: ByteSourceHooks): ByteSource {
  const batcher = new DeterministicBatcher(totalBytes, seed)
  let closed = false
  async function* batches(): AsyncGenerator<Uint8Array> {
    for (;;) {
      if (closed) {
        return
      }
      const batch = batcher.nextBatch()
      if (batch == null) {
        return
      }
      hooks?.onProduced?.(batch.byteLength)
      yield batch
    }
  }
  return {
    batches: batches(),
    digestHex: async () => batcher.digestHex(),
    close: () => {
      closed = true
    }
  }
}

interface WorkerRequest {
  type: 'start'
  totalBytes: string
  seed: string
}

type DatasourceWorkerRequest = import('./datasource.worker').DatasourceWorkerRequest

function createWorkerByteSource(totalBytes: bigint, seed: bigint, hooks?: ByteSourceHooks): ByteSource {
  const worker: Worker = new Worker(new URL('./datasource.worker.ts', import.meta.url), { type: 'module' })
  const request: WorkerRequest = { type: 'start', totalBytes: totalBytes.toString(), seed: seed.toString() }
  worker.postMessage(request)
  let failure: Error | undefined
  const queue: Array<{ data: Uint8Array }> = []
  let doneSeen = false
  let notify: (() => void) | undefined
  let terminated = false

  worker.onmessage = (evt: MessageEvent) => {
    const msg = evt.data as { type: string; data?: ArrayBuffer; error?: string }
    if (msg.type === 'batch' && msg.data != null) {
      hooks?.onProduced?.(msg.data.byteLength)
      queue.push({ data: new Uint8Array(msg.data) })
      notify?.()
    } else if (msg.type === 'done') {
      doneSeen = true
      notify?.()
    } else if (msg.type === 'error') {
      failure = new Error(msg.error ?? 'worker failure')
      notify?.()
    }
  }
  worker.onerror = (evt) => {
    failure = new Error(evt.message)
    notify?.()
  }

  async function* batches(): AsyncGenerator<Uint8Array> {
    for (;;) {
      while (queue.length === 0 && failure == null && !terminated && !doneSeen) {
        await new Promise<void>((resolve) => {
          notify = resolve
        })
        notify = undefined
      }
      if (failure != null) {
        throw failure
      }
      if (terminated) {
        return
      }
      const item = queue.shift()
      if (item != null) {
        if (!doneSeen) {
          worker.postMessage({ type: 'ack' } satisfies DatasourceWorkerRequest)
        }
        yield item.data
        continue
      }
      if (doneSeen) {
        return
      }
    }
  }

  async function digestHex(): Promise<string> {
    while (!doneSeen && failure == null && !terminated) {
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 10)
      })
    }
    if (failure != null) {
      throw failure
    }
    return await new Promise<string>((resolve, reject) => {
      worker.onmessage = (evt: MessageEvent) => {
        const msg = evt.data as { type: string; digest?: string; error?: string }
        if (msg.type === 'digest' && msg.digest != null) {
          resolve(msg.digest)
        } else if (msg.type === 'error') {
          reject(new Error(msg.error ?? 'worker digest failure'))
        }
      }
      worker.onerror = (evt) => reject(new Error(evt.message))
      worker.postMessage({ type: 'digest' })
    })
  }

  return {
    batches: batches(),
    digestHex,
    close: () => {
      terminated = true
      notify?.()
      worker.terminate()
    }
  }
}

export async function runIdentityClient(stream: Stream): Promise<IdentityDiagnostics> {
  const raw = await readAllUntilEof(stream, 16 * 1024)
  try {
    return JSON.parse(new TextDecoder().decode(raw)) as IdentityDiagnostics
  } catch (err) {
    throw new Error('identity response was not valid JSON', { cause: err })
  }
}

export async function handleIdentityStream(ctx: LabStreamContext): Promise<void> {
  const diag: IdentityDiagnostics = {
    remote_peer_id: ctx.info.remotePeerId,
    remote_public_key_hex: ctx.info.remotePublicKeyHex ?? '',
    local_peer_id: ctx.info.localPeerId,
    local_public_key_hex: ctx.info.localPublicKeyHex ?? '',
    direction: ctx.info.direction,
    direct: ctx.info.direct,
    limited: ctx.info.limited,
    transport: ctx.info.transport
  }
  const payload = new TextEncoder().encode(JSON.stringify(diag) + '\n')
  await sendAll(ctx.stream, [payload])
  await ctx.stream.close()
}

export interface EchoResult {
  payloadLength: number
  sentSha256: string
  receivedSha256: string
  matches: boolean
}

export async function runEchoClient(
  stream: Stream,
  payload: Uint8Array,
  signal?: AbortSignal
): Promise<EchoResult> {
  const sentHash = new IncrementalSha256()
  sentHash.update(payload)
  await sendAll(stream, chunkForWrite(encodeEchoFrame(payload)), signal)
  await stream.close()
  const response = await readAllUntilEof(stream, ECHO_MAX_PAYLOAD_BYTES + 8)
  const echoed = parseEchoFrame(response)
  const receivedHash = new IncrementalSha256()
  receivedHash.update(echoed)
  const sentDigest = sentHash.digestHex()
  const receivedDigest = receivedHash.digestHex()
  return {
    payloadLength: echoed.byteLength,
    sentSha256: sentDigest,
    receivedSha256: receivedDigest,
    matches: sentDigest === receivedDigest && echoed.byteLength === payload.byteLength
  }
}

export async function handleEchoStream(ctx: LabStreamContext): Promise<void> {
  const request = await readAllUntilEof(ctx.stream, ECHO_MAX_PAYLOAD_BYTES + 8)
  const payload = parseEchoFrame(request)
  await sendAll(ctx.stream, chunkForWrite(encodeEchoFrame(payload)))
  await ctx.stream.close()
}

export interface BytesRunResult {
  totalBytesReceived: number
  digestHex: string
  trailerDigestHex: string
  digestMatches: boolean
  lengthMatches: boolean
}

class BytesResponseParser {
  private pending = new Uint8Array(0)
  private headerSeen = false
  private readonly hasher = new IncrementalSha256()
  private payloadBytes = 0
  announcedTotal = 0n

  consume(flat: Uint8Array): void {
    if (flat.byteLength === 0) {
      return
    }
    const merged = new Uint8Array(this.pending.byteLength + flat.byteLength)
    merged.set(this.pending)
    merged.set(flat, this.pending.byteLength)
    this.pending = merged
    if (!this.headerSeen) {
      if (this.pending.byteLength < BYTES_RESPONSE_HEADER_LEN) {
        return
      }
      const parsed = parseBytesResponsePrefix(this.pending)
      this.announcedTotal = parsed.totalBytes
      this.headerSeen = true
      this.pending = this.pending.subarray(parsed.consumed)
    }
    const consumable = Math.max(this.pending.byteLength - BYTES_TRAILER_LEN, 0)
    if (consumable > 0) {
      this.hasher.update(this.pending.subarray(0, consumable))
      this.payloadBytes += consumable
      this.pending = this.pending.slice(consumable)
    }
  }

  finish(): { digestHex: string; trailerDigestHex: string } {
    if (!this.headerSeen) {
      throw new Error('no bytes response header received')
    }
    if (BigInt(this.payloadBytes) > this.announcedTotal) {
      throw new Error(`server sent more payload than announced: ${this.payloadBytes} > ${this.announcedTotal}`)
    }
    if (this.pending.byteLength !== BYTES_TRAILER_LEN) {
      throw new Error(`bytes response incomplete: got ${this.payloadBytes}/${this.announcedTotal} payload bytes and ${this.pending.byteLength} tail bytes`)
    }
    const trailerDigestHex = toHex(this.pending)
    return { digestHex: this.hasher.digestHex(), trailerDigestHex }
  }

  get receivedPayloadBytes(): number {
    return this.payloadBytes
  }

  get sawHeader(): boolean {
    return this.headerSeen
  }
}

export async function runBytesClient(
  stream: Stream,
  request: BytesRequest,
  onFirstByte?: () => void,
  onData?: (bytes: number) => void,
  signal?: AbortSignal
): Promise<BytesRunResult> {
  await sendAll(stream, [encodeBytesRequest(request)], signal)
  await stream.close()
  const parser = new BytesResponseParser()
  let firstByteFired = false
  for await (const buf of stream) {
    const flat = flatten(buf)
    if (!firstByteFired && flat.byteLength > 0) {
      firstByteFired = true
      onFirstByte?.()
    }
    parser.consume(flat)
    if (parser.sawHeader && parser.announcedTotal !== request.totalBytes) {
      throw new Error(`server announced ${parser.announcedTotal} bytes but client requested ${request.totalBytes}`)
    }
    onData?.(flat.byteLength)
  }
  const { digestHex, trailerDigestHex } = parser.finish()
  return {
    totalBytesReceived: parser.receivedPayloadBytes,
    digestHex,
    trailerDigestHex,
    digestMatches: digestHex === trailerDigestHex,
    lengthMatches: BigInt(parser.receivedPayloadBytes) === request.totalBytes
  }
}

export async function handleBytesStream(
  ctx: LabStreamContext,
  onSent?: (total: bigint) => void,
  hooks?: { onFirstByte?: () => void }
): Promise<bigint> {
  const requestRaw = await readAllUntilEof(ctx.stream, 20)
  const request = parseBytesRequest(requestRaw)
  await sendOne(ctx.stream, encodeBytesResponseHeader(request.totalBytes))
  const source = createByteSource(request.totalBytes, request.seed)
  let sent = 0n
  let firstByteFired = false
  try {
    for await (const batch of source.batches) {
      if (!firstByteFired) {
        firstByteFired = true
        hooks?.onFirstByte?.()
      }
      await sendOne(ctx.stream, batch)
      sent += BigInt(batch.byteLength)
    }
    const digestHex = await source.digestHex()
    await sendOne(ctx.stream, encodeBytesTrailer(digestHex))
  } finally {
    source.close()
  }
  await ctx.stream.close()
  onSent?.(sent)
  return sent
}

export function connTransportKind(conn: Connection): string {
  const addrStr = conn.remoteAddr.toString()
  if (addrStr.includes('/webrtc-direct')) {
    return 'webrtc-direct'
  }
  if (addrStr.includes('/p2p-circuit')) {
    return 'circuit-relay'
  }
  if (addrStr.includes('/webrtc')) {
    return 'webrtc'
  }
  if (addrStr.includes('/webtransport')) {
    return 'webtransport'
  }
  if (addrStr.includes('/quic')) {
    return 'quic'
  }
  if (addrStr.includes('/ws') || addrStr.includes('/wss')) {
    return 'websocket'
  }
  if (addrStr.includes('/tcp')) {
    return 'tcp'
  }
  return 'unknown'
}
