import { multiaddr, type Multiaddr } from '@multiformats/multiaddr'
import { WebRTC } from '@multiformats/multiaddr-matcher'
import type { Libp2p } from 'libp2p'
import type { Connection, Stream } from '@libp2p/interface'
import {
  PROTOCOL_IDENTITY,
  PROTOCOL_ECHO,
  PROTOCOL_BYTES,
  handleIdentityStream,
  handleEchoStream,
  handleBytesStream,
  connTransportKind
} from './protocols'
import { publicKeyHexFromPeerId, peerIdFromCompressedPublicKeyHex } from './direct'
import type { LabIdentity } from './identity'

export function connInfoOf(connection: Connection, identity: LabIdentity) {
  return {
    remotePeerId: connection.remotePeer.toString(),
    remotePublicKeyHex: publicKeyHexFromPeerId(connection.remotePeer),
    localPeerId: identity.peerId.toString(),
    localPublicKeyHex: identity.publicKeyHex,
    direction: String(connection.direction ?? 'unknown'),
    direct: connection.direct === true,
    limited: connection.limits != null,
    transport: connTransportKind(connection)
  }
}

export class ApprovalRegistry {
  private readonly approved = new Map<string, { approvedAt: string; remotePeerId: string }>()
  private expectedPeerId: string | undefined

  setExpectedPeerId(remotePeerId: string): void {
    this.expectedPeerId = remotePeerId
  }

  isExpected(remotePeerId: string): boolean {
    return this.expectedPeerId != null && remotePeerId === this.expectedPeerId
  }

  approve(connId: string, remotePeerId: string): void {
    this.approved.set(connId, { approvedAt: new Date().toISOString(), remotePeerId })
  }

  has(connId: string): boolean {
    return this.approved.has(connId)
  }

  clear(): void {
    this.approved.clear()
    this.expectedPeerId = undefined
  }

  size(): number {
    return this.approved.size
  }
}

export type LabEventHandler = (event: Record<string, unknown>) => void

export interface LabServerOptions {
  node: Libp2p
  identity: LabIdentity
  approvals: ApprovalRegistry
  onEvent: LabEventHandler
  approvalWaitMs?: number
}

export async function registerLabProtocolHandlers(options: LabServerOptions): Promise<void> {
  const { node, identity } = options
  await node.handle([PROTOCOL_IDENTITY], async (stream, connection) => {
    await serveIfApproved('identity', stream, connection, options, () =>
      handleIdentityStream({ stream, info: connInfoOf(connection, identity) })
    )
  })
  await node.handle([PROTOCOL_ECHO], async (stream, connection) => {
    await serveIfApproved('echo', stream, connection, options, () =>
      handleEchoStream({ stream, info: connInfoOf(connection, identity) })
    )
  })
  await node.handle([PROTOCOL_BYTES], async (stream, connection) => {
    let sentTotal = 0n
    await serveIfApproved(
      'bytes',
      stream,
      connection,
      options,
      async () => {
        sentTotal = await handleBytesStream({ stream, info: connInfoOf(connection, identity) }, (total) => {
          sentTotal = total
        })
      },
      () => ({ bytes_sent: Number(sentTotal) })
    )
  })
}

export const DEFAULT_APPROVAL_WAIT_MS = 30_000

export async function waitForApproval(
  approvals: ApprovalRegistry,
  connId: string,
  waitMs: number,
  pollMs = 100
): Promise<boolean> {
  const deadline = Date.now() + waitMs
  for (;;) {
    if (approvals.has(connId)) {
      return true
    }
    if (Date.now() >= deadline) {
      return false
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs))
  }
}

export async function serveIfApproved(
  protocol: string,
  stream: Stream,
  connection: Connection,
  options: LabServerOptions,
  serve: () => Promise<void>,
  extra?: () => Record<string, unknown>
): Promise<void> {
  const base = {
    protocol,
    side: 'browser',
    remote_peer_id: connection.remotePeer.toString(),
    direct: connection.direct === true,
    limited: connection.limits != null,
    transport: connTransportKind(connection)
  }
  if (connection.limits != null || connection.direct !== true) {
    options.onEvent({ event: 'lab_protocol_denied', error_code: 'limited or relayed connection', ...base })
    stream.abort(new Error('limited or relayed connection'))
    return
  }
  if (!options.approvals.has(connection.id)) {
    const isExpectedDialer = options.approvals.isExpected(connection.remotePeer.toString())
    if (!isExpectedDialer) {
      options.onEvent({ event: 'lab_protocol_denied', error_code: 'connection not approved by inbound gate', ...base })
      stream.abort(new Error('connection not approved'))
      return
    }
    const waitMs = options.approvalWaitMs ?? DEFAULT_APPROVAL_WAIT_MS
    options.onEvent({
      event: 'lab_protocol_pending_approval',
      wait_ms: waitMs,
      ...base
    })
    const approvedInTime = await waitForApproval(options.approvals, connection.id, waitMs)
    if (!approvedInTime) {
      options.onEvent({ event: 'lab_protocol_denied', error_code: 'approval timeout while waiting for listener gate', ...base })
      stream.abort(new Error('approval timeout'))
      return
    }
  }
  try {
    await serve()
    options.onEvent({ event: 'protocol_served', ...base, ...extra?.() })
  } catch (err) {
    options.onEvent({
      event: 'protocol_error',
      error_code: String((err as Error).message).slice(0, 200),
      ...base,
      ...extra?.()
    })
    try {
      stream.abort(err as Error)
    } catch {}
  }
}

export interface ReservationOutcome {
  webRTCMultiaddr: string
  allMultiaddrs: string[]
}

export async function establishReservation(
  node: Libp2p,
  relayMultiaddrInput: string,
  timeoutMs = 60_000
): Promise<ReservationOutcome> {
  const relayMa = parseMultiaddr(relayMultiaddrInput)
  await node.dial(relayMa, { signal: AbortSignal.timeout(30_000) })
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const webRTCAddr = node.getMultiaddrs().find((ma) => WebRTC.matches(ma))
    if (webRTCAddr != null) {
      return {
        webRTCMultiaddr: webRTCAddr.toString(),
        allMultiaddrs: node.getMultiaddrs().map((ma) => ma.toString())
      }
    }
    await sleep(250)
  }
  throw new Error('timed out waiting for circuit relay v2 reservation /webrtc address')
}

export interface PrivateDialOutcome {
  signalingConn: Connection
  directConn: Connection
}

export async function dialPrivateBehindRelay(
  node: Libp2p,
  targetWebRTCMultiaddrInput: string,
  options?: {
    timeoutMs?: number
  }
): Promise<PrivateDialOutcome> {
  const targetMa = parseMultiaddr(targetWebRTCMultiaddrInput)
  const signalingConn = await node.dial(targetMa, { signal: AbortSignal.timeout(30_000) })
  const remote = signalingConn.remotePeer
  const deadline = Date.now() + (options?.timeoutMs ?? 90_000)
  let directConn: Connection | undefined
  while (Date.now() < deadline) {
    const conns = node.getConnections(remote).filter(isWebRtcDirectConn)
    if (conns.length > 0) {
      directConn = conns[conns.length - 1]
      break
    }
    await sleep(250)
  }
  if (directConn == null) {
    throw new Error('timed out waiting for direct WebRTC connection behind relay signaling')
  }
  return { signalingConn, directConn }
}

export interface InboundWaitResult {
  conn: Connection
}

export interface InboundPreCheck {
  ok: boolean
  failures: string[]
}

export function classifyInboundConn(conn: Connection): InboundPreCheck {
  const failures: string[] = []
  if (conn.direct !== true) {
    failures.push('connection is not direct (relay or unknown path)')
  }
  if (conn.limits != null) {
    failures.push('connection has limits')
  }
  const transport = connTransportKind(conn)
  if (transport !== 'webrtc' && transport !== 'webrtc-direct') {
    failures.push(`inbound transport must be webrtc, got ${transport}`)
  }
  return { ok: failures.length === 0, failures }
}

export async function waitForApprovedInboundConnection(input: {
  node: Libp2p
  expectedDialerPublicKeyHex: string
  timeoutMs?: number
}): Promise<InboundWaitResult> {
  const expectedPeerId = peerIdFromCompressedPublicKeyHex(input.expectedDialerPublicKeyHex.trim()).toString()
  const deadline = Date.now() + (input.timeoutMs ?? 300_000)
  let lastWrongPeerHint = ''
  for (;;) {
    const candidates = input.node.getConnections().filter((c) => isWebRtcDirectConn(c))
    for (const conn of candidates) {
      if (conn.remotePeer.toString() !== expectedPeerId) {
        lastWrongPeerHint = conn.remotePeer.toString()
        continue
      }
      const preCheck = classifyInboundConn(conn)
      if (!preCheck.ok) {
        throw new Error(`expected dialer connected but inbound pre-check failed: ${preCheck.failures.join('; ')}`)
      }
      return { conn }
    }
    if (Date.now() >= deadline) {
      const hint = lastWrongPeerHint !== '' ? `; saw unrelated peer ${lastWrongPeerHint}` : ''
      throw new Error(`timed out waiting for approved dialer connection (expected peer ${expectedPeerId})${hint}`)
    }
    await sleep(250)
  }
}

export function isWebRtcDirectConn(conn: Connection): boolean {
  const addr = conn.remoteAddr.toString()
  return addr.includes('/webrtc') && !addr.includes('/p2p-circuit')
}

export async function waitForWebRtcDirectConnection(node: Libp2p, timeoutMs = 120_000): Promise<Connection> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    const found = node.getConnections().find(isWebRtcDirectConn)
    if (found != null) {
      return found
    }
    await sleep(250)
  }
  throw new Error('timed out waiting for a direct WebRTC connection')
}

function parseMultiaddr(text: string): Multiaddr {
  try {
    return multiaddr(text.trim())
  } catch (err) {
    throw new Error(`invalid multiaddr: ${text.trim()}`, { cause: err })
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
