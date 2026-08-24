import { publicKeyFromProtobuf, publicKeyFromRaw } from '@libp2p/crypto/keys'
import { peerIdFromPublicKey } from '@libp2p/peer-id'
import type { Libp2p } from 'libp2p'
import type { Connection, PeerId, Stream } from '@libp2p/interface'
import type { Multiaddr } from '@multiformats/multiaddr'
import {
  PROTOCOL_IDENTITY,
  PROTOCOL_ECHO,
  PROTOCOL_BYTES,
  runIdentityClient,
  runEchoClient,
  runBytesClient,
  connTransportKind,
  type BytesRequest,
  type BytesRunResult,
  type EchoResult,
  type IdentityDiagnostics
} from './protocols'
import { fromHex, toHex, fillRandom } from './identity'
import { isPairAllowedForTransfer, type SelectedCandidatePair } from './stats'

export const IDENTITY_MULTICODEC = 0x00

export function publicKeyHexFromPeerId(peerId: PeerId): string | undefined {
  try {
    const multihash = peerId.toMultihash()
    if (multihash.code !== IDENTITY_MULTICODEC) {
      return undefined
    }
    const pub = publicKeyFromProtobuf(multihash.digest)
    if (pub.type !== 'secp256k1') {
      return undefined
    }
    return toHex(pub.raw)
  } catch {
    return undefined
  }
}

export function peerIdFromCompressedPublicKeyHex(hex: string): PeerId {
  const bytes = fromHex(hex)
  if (bytes.length !== 33 || (bytes[0] !== 0x02 && bytes[0] !== 0x03)) {
    throw new Error('expected 33-byte compressed secp256k1 public key hex')
  }
  return peerIdFromPublicKey(publicKeyFromRaw(bytes))
}

export interface DirectGateResult {
  ok: boolean
  expectedPeerId: string
  observedPeerId: string
  failures: string[]
  transport: string
  direct: boolean
  limited: boolean
  candidatePairSummary: string
}

export function evaluateDirectGate(input: {
  conn: Connection
  expectedPublicKeyHex: string
  selectedPair?: SelectedCandidatePair | undefined
}): DirectGateResult {
  const failures: string[] = []
  let expectedPeerId = ''
  try {
    expectedPeerId = peerIdFromCompressedPublicKeyHex(input.expectedPublicKeyHex.trim()).toString()
  } catch (err) {
    failures.push(`invalid pinned public key: ${(err as Error).message}`)
  }
  const observedPeerId = input.conn.remotePeer.toString()
  if (expectedPeerId !== '' && observedPeerId !== expectedPeerId) {
    failures.push(`remote peer id mismatch: pinned ${expectedPeerId} vs observed ${observedPeerId}`)
  }
  const direct = input.conn.direct === true
  if (!direct) {
    failures.push('connection is not direct (relay or unknown path)')
  }
  const limitsAbsent = input.conn.limits == null
  if (!limitsAbsent) {
    failures.push(`connection has limits: ${safeStringify(input.conn.limits)}`)
  }
  const pair = input.selectedPair
  let candidatePairSummary = 'unavailable'
  if (pair != null) {
    candidatePairSummary = `${pair.localCandidateType}<->${pair.remoteCandidateType}`
    if (!isPairAllowedForTransfer(pair)) {
      failures.push(
        `selected ICE candidate pair not allowed for transfer: ${pair.localCandidateType}<->${pair.remoteCandidateType} (only host/srflx/prflx accepted)`
      )
    }
  } else {
    failures.push('no selected ICE candidate pair observed yet')
  }
  return {
    ok: failures.length === 0,
    expectedPeerId,
    observedPeerId,
    failures,
    transport: connTransportKind(input.conn),
    direct,
    limited: !limitsAbsent,
    candidatePairSummary
  }
}

export async function dialTarget(
  node: Libp2p,
  targetMultiaddr: Multiaddr,
  options?: { signal?: AbortSignal }
): Promise<Connection> {
  if (options?.signal != null) {
    return node.dial(targetMultiaddr, { signal: options.signal })
  }
  return node.dial(targetMultiaddr)
}

export class GateError extends Error {
  readonly gate: DirectGateResult

  constructor(gate: DirectGateResult) {
    super(`direct gate failed: ${gate.failures.join('; ')}`)
    this.name = 'GateError'
    this.gate = gate
  }
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v)
  } catch {
    return String(value)
  }
}

export async function measureRtt(node: Libp2p<Record<string, unknown>>, remote: PeerId): Promise<number | undefined> {
  const services = node.services as { ping?: { ping(peer: PeerId, options?: { signal?: AbortSignal }): Promise<number> } }
  if (services.ping == null) {
    return undefined
  }
  try {
    return await services.ping.ping(remote, { signal: AbortSignal.timeout(10_000) })
  } catch {
    return undefined
  }
}

export interface LabProtocolRun {
  identity?: IdentityDiagnostics
  echo?: EchoResult
  bytes?: BytesRunResult
}

export async function openStream(conn: Connection, protocol: string): Promise<Stream> {
  return conn.newStream(protocol)
}

export async function verifyIdentityOnConnection(input: {
  conn: Connection
  localIdentityPublicKeyHex: string
}): Promise<{ diag: IdentityDiagnostics; problems: string[] }> {
  const stream = await input.conn.newStream(PROTOCOL_IDENTITY)
  const diag = await runIdentityClient(stream)
  const problems: string[] = []
  const localExpectedRemote = peerIdFromCompressedPublicKeyHex(input.localIdentityPublicKeyHex).toString()
  if (diag.remote_peer_id !== localExpectedRemote) {
    problems.push(`NAS saw remote peer ${diag.remote_peer_id} but our business key derives ${localExpectedRemote}`)
  }
  if (diag.remote_public_key_hex.toLowerCase() !== input.localIdentityPublicKeyHex.toLowerCase()) {
    problems.push('NAS observed a different public key than our business public key')
  }
  const remoteKeyHex = publicKeyHexFromPeerId(input.conn.remotePeer)
  if (remoteKeyHex == null) {
    problems.push('could not recover NAS compressed public key from authenticated connection')
  }
  return { diag, problems }
}

export async function echoOnConnection(
  conn: Connection,
  sizes: number[] = [0, 1, 16384, 262144]
): Promise<EchoResult[]> {
  const results: EchoResult[] = []
  for (const size of sizes) {
    const payload = new Uint8Array(size)
    fillRandom(payload)
    const stream = await conn.newStream(PROTOCOL_ECHO)
    results.push(await runEchoClient(stream, payload))
  }
  return results
}

export async function transferBytesOnConnection(
  conn: Connection,
  request: BytesRequest,
  hooks?: {
    onFirstByte?: () => void
    onData?: (bytes: number) => void
    signal?: AbortSignal
  }
): Promise<BytesRunResult> {
  const stream = await conn.newStream(PROTOCOL_BYTES)
  return runBytesClient(stream, request, hooks?.onFirstByte, hooks?.onData, hooks?.signal)
}
