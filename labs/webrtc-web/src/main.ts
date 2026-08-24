import { multiaddr } from '@multiformats/multiaddr'
import type { Libp2p } from 'libp2p'
import type { Connection } from '@libp2p/interface'
import {
  deriveIdentity,
  isTestPrivateKeyHex,
  normalizePrivateKeyHex,
  randomPrivateKeyHex
} from './identity'
import type { LabIdentity } from './identity'
import { DEFAULT_STUN_INPUT, createNode, parseIceServersInput } from './node'
import type { NodeRole } from './node'
import { installPeerConnectionObserver, peakHeapBytes, ThroughputMeter, PeakHeapSampler } from './stats'
import type { PeerConnectionObserver, SelectedCandidatePair } from './stats'
import {
  dialTarget,
  echoOnConnection,
  transferBytesOnConnection,
  verifyIdentityOnConnection,
  measureRtt,
  evaluateDirectGate,
  peerIdFromCompressedPublicKeyHex,
  GateError
} from './direct'
import type { DirectGateResult } from './direct'
import {
  ApprovalRegistry,
  registerLabProtocolHandlers,
  establishReservation,
  dialPrivateBehindRelay,
  waitForApprovedInboundConnection
} from './private'
import { EventLog, appendLogLine, collectDiagnostics, inputValue, on, setText } from './ui'

const log = new EventLog(appendLogLine)

let identity: LabIdentity | undefined
let node: Libp2p | undefined
const approvals = new ApprovalRegistry()
const observer: PeerConnectionObserver | undefined =
  typeof window !== 'undefined' && typeof window.RTCPeerConnection === 'function' ? tryInstallObserver() : undefined

interface ActiveContext {
  connection: Connection
  expectedPublicKeyHex: string
  pcGeneration: number
}

let activeContext: ActiveContext | undefined

function tryInstallObserver(): PeerConnectionObserver | undefined {
  try {
    return installPeerConnectionObserver()
  } catch (err) {
    log.emit('observer_install_failed', { error_code: String((err as Error).message) })
    return undefined
  }
}

function requireObserver(): PeerConnectionObserver {
  if (observer == null) {
    throw new Error('ICE observer unavailable')
  }
  return observer
}

on('btn-generate-key', () => {
  void activateKey(randomPrivateKeyHex()).catch((err) => fail('identity_generate_failed', err))
})

on('btn-import-key', () => {
  const input = inputValue('input-private-key')
  if (!isTestPrivateKeyHex(input)) {
    log.emit('identity_import_rejected', { error_code: 'private key must be exactly 64 hex characters' })
    return
  }
  void activateKey(normalizePrivateKeyHex(input))
    .then(() => {
      const field = document.getElementById('input-private-key') as HTMLInputElement | null
      if (field != null) {
        field.value = ''
      }
    })
    .catch((err) => fail('identity_import_failed', err))
})

async function activateKey(privateKeyHex: string): Promise<void> {
  const derived = deriveIdentity(privateKeyHex)
  stopCurrentNode()
  identity = derived
  setText('id-public-key', derived.publicKeyHex)
  setText('id-peer-id', derived.peerId.toString())
  setText('id-key-match', 'business key == libp2p identity key')
  log.emit('identity_activated', {
    local_peer_id: derived.peerId.toString(),
    public_key_hex: derived.publicKeyHex
  })
}

on('btn-start-node', () => {
  void startNode(currentRole()).catch((err) => fail('node_start_failed', err))
})

on('btn-stop-node', () => {
  stopCurrentNode()
})

function currentRole(): NodeRole {
  const select = document.getElementById('select-role') as HTMLSelectElement | null
  const role = select?.value as NodeRole | undefined
  switch (role) {
    case 'private-listener':
    case 'private-dialer':
      return role
    default:
      return 'direct-dialer'
  }
}

async function startNode(role: NodeRole): Promise<void> {
  const id = identity
  if (id == null) {
    throw new Error('no active identity - generate or import a test key first')
  }
  stopCurrentNode()
  const created = await createNode({
    identity: id,
    role,
    stunInput: inputValue('stun-list') || DEFAULT_STUN_INPUT
  })
  node = created
  await registerLabProtocolHandlers({
    node: created,
    identity: id,
    approvals,
    onEvent: (event) => log.emit(String(event.event), event)
  })
  await created.start()
  const addrs = created.getMultiaddrs().map((ma) => ma.toString())
  setText('node-status', `running (${role})`)
  setText('node-peer-id', created.peerId.toString())
  setText('node-addrs', addrs.length > 0 ? addrs.join('\n') : '(dial-only)')
  log.emit('node_started', { local_peer_id: created.peerId.toString(), role, listen: addrs })
}

function stopCurrentNode(): void {
  const current = node
  node = undefined
  activeContext = undefined
  approvals.clear()
  setText('node-status', 'stopped')
  if (current != null) {
    void (async () => {
      try {
        await current.stop()
        log.emit('node_stopped', { local_peer_id: current.peerId.toString() })
      } catch (err) {
        fail('node_stop_failed', err)
      }
    })()
  }
}

async function requireReady(): Promise<{ id: LabIdentity; host: Libp2p }> {
  const id = identity
  const host = node
  if (id == null || host == null) {
    throw new Error('activate a key and start the node first')
  }
  return { id, host }
}

interface EstablishedFlow {
  connection: Connection
  gate: DirectGateResult
  pair: SelectedCandidatePair
  pcGeneration: number
}

function bindActiveContext(flow: EstablishedFlow, expectedPublicKeyHex: string): void {
  activeContext = {
    connection: flow.connection,
    expectedPublicKeyHex: expectedPublicKeyHex.trim().toLowerCase(),
    pcGeneration: flow.pcGeneration
  }
}

async function gateAfterPair(conn: Connection, expectedKey: string, bound: { pair: SelectedCandidatePair; generation: number }): Promise<EstablishedFlow> {
  const gate = evaluateDirectGate({
    conn,
    expectedPublicKeyHex: expectedKey,
    selectedPair: bound.pair
  })
  if (!gate.ok) {
    throw new GateError(gate)
  }
  return { connection: conn, gate, pair: bound.pair, pcGeneration: bound.generation }
}

on('btn-direct-dial', () => {
  void runDirectFlow().catch((err) => fail('direct_flow_failed', err))
})

async function runDirectFlow(): Promise<void> {
  const { id, host } = await requireReady()
  const targetMa = inputValue('input-nas-multiaddr').trim()
  const expectedKey = inputValue('input-nas-pubkey').replace(/\s+/g, '')
  if (targetMa === '' || expectedKey === '') {
    throw new Error('NAS multiaddr and expected compressed public key are required')
  }
  const obs = requireObserver()
  const generationBefore = obs.currentGeneration()
  log.emit('dial_started', { target: targetMa, pc_generation_before: generationBefore })

  const conn = await dialTarget(host, multiaddr(targetMa))
  const bound = await obs.waitForSelectedPair(generationBefore, 20_000)
  const flow = await gateAfterPair(conn, expectedKey, bound)

  bindActiveContext(flow, expectedKey)
  log.emit('direct_gate_passed', {
    remote_peer_id: flow.gate.observedPeerId,
    transport: flow.gate.transport,
    direct: flow.gate.direct,
    candidate_pair: flow.gate.candidatePairSummary,
    pc_generation: flow.pcGeneration,
    pair_bytes_sent: flow.pair.bytesSent,
    pair_bytes_received: flow.pair.bytesReceived
  })
  renderGate(flow.gate.observedPeerId, flow.gate)
  const rttMs = await measureRtt(host, flow.connection.remotePeer)
  setText('fact-rtt', rttMs != null ? `${rttMs.toFixed(1)} ms` : 'unavailable')

  const verification = await verifyIdentityOnConnection({
    conn: flow.connection,
    localIdentityPublicKeyHex: id.publicKeyHex
  })
  setText('identity-response', JSON.stringify(verification.diag, null, 2))
  log.emit('identity_protocol_done', { problems: verification.problems })
  assertEmpty(verification.problems)

  const echoResults = await echoOnConnection(flow.connection)
  for (const result of echoResults) {
    log.emit('echo_result', {
      remote_peer_id: flow.gate.observedPeerId,
      bytes_sent: result.payloadLength,
      matches: result.matches
    })
    if (!result.matches) {
      throw new Error(`echo mismatch at ${result.payloadLength} bytes`)
    }
  }
  setText('echo-summary', echoResults.map((r) => `${r.payloadLength}B ok`).join(', '))
  enable(['btn-direct-bytes'])
}

on('btn-direct-bytes', () => {
  void runBytesFlow().catch((err) => fail('bytes_flow_failed', err))
})

interface ByteStreamOutcome {
  index: number
  ok: boolean
  bytes: number
  digestMatches: boolean
  lengthMatches: boolean
  ttfbMs: number
  error?: string
}

async function reGateActiveConn(): Promise<DirectGateResult> {
  const ctx = activeContext
  if (ctx == null) {
    throw new Error('no active gated connection - complete a dial flow first')
  }
  const obs = requireObserver()
  const refreshedPair = await obs.refreshGeneration(ctx.pcGeneration)
  const gate = evaluateDirectGate({
    conn: ctx.connection,
    expectedPublicKeyHex: ctx.expectedPublicKeyHex,
    selectedPair: refreshedPair
  })
  if (!gate.ok) {
    throw new GateError(gate)
  }
  return gate
}

async function runBytesFlow(): Promise<void> {
  const gate = await reGateActiveConn()
  const conn = activeContext?.connection
  if (conn == null) {
    throw new Error('no active gated connection')
  }
  const totalGiB = Number(inputValue('input-total-gib') || '1')
  const streamCount = Math.max(1, Math.min(8, Number(inputValue('input-streams') || '1')))
  const blockBytes = Number(inputValue('input-block-bytes') || '262144')
  if (!Number.isFinite(totalGiB) || totalGiB <= 0 || totalGiB > 8) {
    throw new Error('total GiB out of lab range (0, 8]')
  }
  const seedBase = BigInt(Date.now() % 1_000_000_007)
  const perStreamBytes = BigInt(Math.floor((totalGiB * 1024 * 1024 * 1024) / streamCount))
  setText('bytes-progress', 'running...')
  const meter = new ThroughputMeter()
  meter.start()
  const heapSampler = new PeakHeapSampler()
  heapSampler.start()
  let receivedTotal = 0
  const tasks = Array.from({ length: streamCount }, (_, i): Promise<ByteStreamOutcome> => {
    const streamMeter = new ThroughputMeter()
    streamMeter.start()
    return transferBytesOnConnection(
      conn,
      { totalBytes: perStreamBytes, logicalBlockBytes: blockBytes, seed: seedBase + BigInt(i) },
      {
        onFirstByte: () => streamMeter.onFirstByte(),
        onData: (n) => {
          streamMeter.add(n)
          receivedTotal += n
          if ((receivedTotal & 0xfffff) < n) {
            setText('bytes-progress', `${(receivedTotal / 1048576).toFixed(1)} MiB received`)
          }
        },
        signal: AbortSignal.timeout(2 * 3600 * 1000)
      }
    ).then(
      (result): ByteStreamOutcome => ({
        index: i,
        ok: result.digestMatches && result.lengthMatches,
        bytes: result.totalBytesReceived,
        digestMatches: result.digestMatches,
        lengthMatches: result.lengthMatches,
        ttfbMs: streamMeter.finish().ttfbMs
      }),
      (err): ByteStreamOutcome => ({
        index: i,
        ok: false,
        bytes: 0,
        digestMatches: false,
        lengthMatches: false,
        ttfbMs: -1,
        error: String(err.message)
      })
    )
  })
  const results = await Promise.all(tasks)
  const overallStats = meter.finish()
  const elapsedMs = overallStats.elapsedMs
  const heapDeltaPeak = heapSampler.stopAndDelta()
  const totalOk = results.every((r) => r.ok)
  const totalReceived = results.reduce((acc, r) => acc + r.bytes, 0)
  setText('bytes-progress', totalOk
    ? `OK ${totalReceived} bytes in ${(elapsedMs / 1000).toFixed(1)}s (${(receivedTotal / 1048576 / (elapsedMs / 1000)).toFixed(2)} MiB/s)`
    : 'FAILED - see log')
  for (const r of results) {
    if (r.error == null) {
      log.emit('bytes_result', {
        stream: r.index,
        bytes_received: r.bytes,
        digest_matches: r.digestMatches,
        length_matches: r.lengthMatches,
        ttfb_ms: Math.round(r.ttfbMs),
        throughput_mibs: Number((r.bytes / 1048576 / (elapsedMs / 1000)).toFixed(3)),
        peak_heap_delta_bytes: heapDeltaPeak
      })
    } else {
      log.emit('bytes_stream_error', { stream: r.index, error_code: r.error.slice(0, 200) })
    }
  }
  emitCandidateSnapshot()
  log.emit('transfer_gate_refreshed', {
    candidate_pair: gate.candidatePairSummary,
    direct: gate.direct,
    pc_generation: activeContext?.pcGeneration
  })
  if (!totalOk) {
    throw new Error('one or more bytes streams failed digest/length validation')
  }
}

on('btn-reserve-relay', () => {
  void runReservationFlow().catch((err) => fail('reservation_failed', err))
})

async function runReservationFlow(): Promise<void> {
  const { host } = await requireReady()
  const relayAddr = inputValue('input-relay-multiaddr').trim()
  if (relayAddr === '') {
    throw new Error('relay multiaddr required')
  }
  const reservation = await establishReservation(host, relayAddr)
  setText('relay-reservation', reservation.webRTCMultiaddr)
  log.emit('reservation_established', { webrtc_multiaddr: reservation.webRTCMultiaddr })
}

on('btn-private-dial', () => {
  void runPrivateDialFlow().catch((err) => fail('private_dial_failed', err))
})

async function runPrivateDialFlow(): Promise<void> {
  const { id, host } = await requireReady()
  const target = inputValue('input-target-multiaddr').trim()
  const expectedKey = inputValue('input-target-pubkey').replace(/\s+/g, '')
  if (target === '' || expectedKey === '') {
    throw new Error('target listener multiaddr and expected public key are required')
  }
  const obs = requireObserver()
  const generationBefore = obs.currentGeneration()
  log.emit('private_dial_started', { pc_generation_before: generationBefore })

  const outcome = await dialPrivateBehindRelay(host, target)
  const bound = await obs.waitForSelectedPair(generationBefore, 20_000)
  const flow = await gateAfterPair(outcome.directConn, expectedKey, bound)

  bindActiveContext(flow, expectedKey)
  approvals.approve(flow.connection.id, flow.gate.observedPeerId)
  log.emit('private_gate_passed', {
    remote_peer_id: flow.gate.observedPeerId,
    candidate_pair: flow.gate.candidatePairSummary,
    direct: flow.gate.direct,
    pc_generation: flow.pcGeneration,
    pair_bytes_sent: flow.pair.bytesSent,
    pair_bytes_received: flow.pair.bytesReceived
  })
  renderGate(flow.gate.observedPeerId, flow.gate)

  const verification = await verifyIdentityOnConnection({
    conn: flow.connection,
    localIdentityPublicKeyHex: id.publicKeyHex
  })
  setText('identity-response', JSON.stringify(verification.diag, null, 2))
  assertEmpty(verification.problems)

  const echoResults = await echoOnConnection(flow.connection)
  setText('echo-summary', echoResults.map((r) => `${r.payloadLength}B ok`).join(', '))
  enable(['btn-direct-bytes'])
}

on('btn-wait-incoming', () => {
  void runWaitIncomingFlow().catch((err) => fail('incoming_wait_failed', err))
})

async function runWaitIncomingFlow(): Promise<void> {
  const { host } = await requireReady()
  const expectedDialerKey = inputValue('input-dialer-pubkey').replace(/\s+/g, '')
  if (expectedDialerKey === '') {
    throw new Error('expected dialer compressed public key is required (listener must authenticate dialers)')
  }
  const expectedDialerPeerId = peerIdFromCompressedPublicKeyHex(expectedDialerKey).toString()
  approvals.setExpectedPeerId(expectedDialerPeerId)
  const obs = requireObserver()
  const generationBefore = obs.currentGeneration()
  log.emit('waiting_incoming_webrtc', { expected_dialer_peer_id: expectedDialerPeerId })

  const result = await waitForApprovedInboundConnection({
    node: host,
    expectedDialerPublicKeyHex: expectedDialerKey,
    timeoutMs: 300_000
  })
  const bound = await obs.waitForSelectedPair(generationBefore, 20_000)
  const gate = evaluateDirectGate({
    conn: result.conn,
    expectedPublicKeyHex: expectedDialerKey,
    selectedPair: bound.pair
  })
  if (gate.transport !== 'webrtc' && gate.transport !== 'webrtc-direct') {
    gate.failures.push(`inbound transport must be webrtc, got ${gate.transport}`)
    gate.ok = false
  }
  if (!gate.ok) {
    throw new GateError(gate)
  }

  const flow: EstablishedFlow = {
    connection: result.conn,
    gate,
    pair: bound.pair,
    pcGeneration: bound.generation
  }
  bindActiveContext(flow, expectedDialerKey)
  approvals.approve(result.conn.id, result.conn.remotePeer.toString())
  log.emit('incoming_webrtc_approved', {
    remote_peer_id: result.conn.remotePeer.toString(),
    connection_id: result.conn.id,
    direct: gate.direct,
    candidate_pair: gate.candidatePairSummary,
    pc_generation: bound.generation
  })
  renderGate(gate.observedPeerId, gate)
  enable(['btn-direct-bytes'])
}

function emitCandidateSnapshot(): void {
  if (observer == null) {
    return
  }
  for (const snap of observer.list()) {
    log.emit('candidate_pair_snapshot', {
      pc_generation: snap.generation,
      samples: snap.samples,
      local_candidate_type: snap.pair?.localCandidateType,
      remote_candidate_type: snap.pair?.remoteCandidateType,
      bytes_sent: snap.pair?.bytesSent ?? 0,
      bytes_received: snap.pair?.bytesReceived ?? 0
    })
  }
}

function renderGate(remotePeerId: string, gate: DirectGateResult): void {
  setText('fact-remote-peer-id', remotePeerId)
  setText('fact-direct', String(gate.direct))
  setText('fact-limits', String(gate.limited))
  setText('fact-transport', gate.transport)
  setText('fact-candidate-pair', gate.candidatePairSummary)
}

function enable(ids: string[]): void {
  for (const id of ids) {
    const btn = document.getElementById(id) as HTMLButtonElement | null
    if (btn != null) {
      btn.disabled = false
    }
  }
}

function assertEmpty(problems: string[]): void {
  if (problems.length > 0) {
    throw new Error(`identity verification failed: ${problems.join('; ')}`)
  }
}

function fail(event: string, err: unknown): void {
  const message = err instanceof Error ? err.message : String(err)
  const fields: Record<string, unknown> = { error_code: message.slice(0, 300) }
  if (err instanceof GateError) {
    fields['gate_failures'] = err.gate.failures
  }
  log.emit(event, fields)
}

void bootDiagnostics()

async function bootDiagnostics(): Promise<void> {
  const stunInput = inputValue('stun-list') || DEFAULT_STUN_INPUT
  const parsedIce = parseIceServersInput(stunInput)
  const diag = collectDiagnostics(stunInput)
  diag.turnRejections = parsedIce.rejected
  setText('diag-secure-context', String(diag.isSecureContext))
  setText('diag-user-agent', diag.userAgent)
  setText('diag-webrtc-available', String(diag.webRTCAvailable))
  setText('diag-stun-list', diag.stunList)
  setText('diag-turn-status', parsedIce.turnRejected ? `REJECTED: ${parsedIce.rejected.join(', ')}` : 'none configured (ok)')
  if (!diag.isSecureContext) {
    log.emit('insecure_context_warning', {})
  }
}
