import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import type { Libp2p } from 'libp2p'
import type { Connection } from '@libp2p/interface'
import { deriveIdentity } from '../src/identity'
import { classifyInboundConn, waitForApprovedInboundConnection } from '../src/private'
import { evaluateDirectGate, peerIdFromCompressedPublicKeyHex } from '../src/direct'
import { samplePair, isPairAllowedForTransfer } from '../src/stats'
import type { SelectedCandidatePair } from '../src/stats'

const vectorPath = fileURLToPath(new URL('../testdata/identity-vector.json', import.meta.url))
const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
  private_key_hex: string
  public_key_hex: string
}

function fakeConn(input: {
  remotePeerIdText: string
  direct?: boolean
  limits?: Record<string, unknown> | null
  transport?: string
}): Connection {
  const addrSuffix = input.transport ?? 'webrtc-direct'
  return {
    id: `conn-${Math.random().toString(36).slice(2)}`,
    remotePeer: { toString: () => input.remotePeerIdText },
    direct: input.direct ?? true,
    limits: input.limits === undefined ? null : input.limits,
    remoteAddr: {
      toString: () => `/ip4/1.2.3.4/udp/4001/${addrSuffix}/certhash/x`
    }
  } as unknown as Connection
}

function mockNode(conns: Connection[]): Libp2p {
  return {
    getConnections: () => conns
  } as unknown as Libp2p
}

describe('listener inbound flow (issue: authenticate dialer before serving)', () => {
  const dialerIdentity = deriveIdentity(vector.private_key_hex)
  const expectedKeyHex = dialerIdentity.publicKeyHex

  it('derives the expected dialer PeerId from a 66-char compressed public key', () => {
    expect(expectedKeyHex).toHaveLength(66)
    const peerId = peerIdFromCompressedPublicKeyHex(expectedDialerKeyInput())
    expect(peerId.toString()).toBe(dialerIdentity.peerId.toString())
  })

  function expectedDialerKeyInput(): string {
    return expectedKeyHex
  }

  it('approves a matching direct unlimited webrtc connection immediately', async () => {
    const conn = fakeConn({ remotePeerIdText: dialerIdentity.peerId.toString() })
    const result = await waitForApprovedInboundConnection({
      node: mockNode([conn]),
      expectedDialerPublicKeyHex: expectedDialerKeyInput(),
      timeoutMs: 1500
    })
    expect(result.conn.id).toBe(conn.id)
  })

  it('keeps waiting when only an unrelated peer is connected, then times out', async () => {
    const stranger = deriveIdentity('22'.repeat(32))
    const conn = fakeConn({ remotePeerIdText: stranger.peerId.toString() })
    await expect(
      waitForApprovedInboundConnection({
        node: mockNode([conn]),
        expectedDialerPublicKeyHex: expectedDialerKeyInput(),
        timeoutMs: 900
      })
    ).rejects.toThrow(/timed out waiting for approved dialer connection/)
  }, 10_000)

  it('fails fast when the expected dialer arrives over a relayed or limited connection', async () => {
    const relayed = fakeConn({
      remotePeerIdText: dialerIdentity.peerId.toString(),
      direct: false,
      limits: { bytes: 1n }
    })
    await expect(
      waitForApprovedInboundConnection({
        node: mockNode([relayed]),
        expectedDialerPublicKeyHex: expectedDialerKeyInput(),
        timeoutMs: 5000
      })
    ).rejects.toThrow(/inbound pre-check failed/)
  }, 10_000)

  it('classifyInboundConn rejects non-webrtc transports', () => {
    const tcp = fakeConn({ remotePeerIdText: dialerIdentity.peerId.toString(), transport: 'tcp' })
    const check = classifyInboundConn(tcp)
    expect(check.ok).toBe(false)
    expect(check.failures.some((f) => f.includes('transport must be webrtc'))).toBe(true)
  })
})

describe('direct gate strict candidate whitelist (issue: unknown must fail)', () => {
  const identity = deriveIdentity(vector.private_key_hex)

  function gateWith(localType: string, remoteType: string) {
    return evaluateDirectGate({
      conn: fakeConn({ remotePeerIdText: identity.peerId.toString() }),
      expectedPublicKeyHex: identity.publicKeyHex,
      selectedPair: makePair(localType, remoteType)
    })
  }

  it('accepts host/srflx/prflx pairs only', () => {
    for (const t of ['host', 'srflx', 'prflx']) {
      expect(gateWith(t, t).ok).toBe(true)
      expect(isPairAllowedForTransfer(makePair(t, t))).toBe(true)
    }
  })

  it('rejects relay and unknown candidate types on either side', () => {
    for (const bad of ['relay', 'unknown']) {
      expect(gateWith(bad, 'host').ok).toBe(false)
      expect(gateWith('host', bad).ok).toBe(false)
      expect(isPairAllowedForTransfer(makePair(bad, 'host'))).toBe(false)
      expect(isPairAllowedForTransfer(makePair('host', bad))).toBe(false)
    }
    const gate = gateWith('unknown', 'unknown')
    expect(gate.failures.some((f) => f.includes('only host/srflx/prflx accepted'))).toBe(true)
  })
})

function makePair(localType: string, remoteType: string): SelectedCandidatePair {
  return {
    localCandidateType: localType as SelectedCandidatePair['localCandidateType'],
    remoteCandidateType: remoteType as SelectedCandidatePair['remoteCandidateType'],
    localCandidateId: `${localType}-l`,
    remoteCandidateId: `${remoteType}-r`,
    bytesSent: 1,
    bytesReceived: 1,
    currentRttMs: 5,
    state: 'succeeded',
    nominated: true,
    selected: true,
    source: 'fallback-scoring',
    sampledAt: new Date().toISOString()
  }
}

interface FakeStat {
  type: string
  id: string
  [key: string]: unknown
}

function fakeReport(stats: FakeStat[]): RTCStatsReport {
  const map = new Map(stats.map((s) => [s.id, s]))
  return {
    forEach(cb: (s: unknown) => void): void {
      for (const s of stats) cb(s)
    },
    get(id: string): unknown {
      return map.get(id)
    }
  } as unknown as RTCStatsReport
}

function fakePc(report: RTCStatsReport): RTCPeerConnection {
  return {
    getStats: async () => report
  } as unknown as RTCPeerConnection
}

describe('samplePair selected-pair source preference', () => {
  const nominatedPair: FakeStat = {
    type: 'candidate-pair',
    id: 'pair-a',
    state: 'succeeded',
    nominated: true,
    bytesSent: 999999,
    bytesReceived: 999999,
    localCandidateId: 'host-l',
    remoteCandidateId: 'host-r'
  }
  const realSelectedPair: FakeStat = {
    type: 'candidate-pair',
    id: 'pair-b',
    state: 'succeeded',
    nominated: false,
    bytesSent: 1,
    bytesReceived: 1,
    localCandidateId: 'srflx-l',
    remoteCandidateId: 'prflx-r'
  }

  it('prefers transport.selectedCandidatePairId when the browser provides it', async () => {
    const report = fakeReport([
      nominatedPair,
      realSelectedPair,
      { type: 'transport', id: 't1', selectedCandidatePairId: 'pair-b' },
      { type: 'local-candidate', id: 'srflx-l', candidateType: 'srflx' },
      { type: 'remote-candidate', id: 'prflx-r', candidateType: 'prflx' },
      { type: 'local-candidate', id: 'host-l', candidateType: 'host' },
      { type: 'remote-candidate', id: 'host-r', candidateType: 'host' }
    ])
    const pair = await samplePair(fakePc(report))
    expect(pair?.source).toBe('transport-selected-pair')
    expect(pair?.localCandidateType).toBe('srflx')
    expect(pair?.remoteCandidateType).toBe('prflx')
  })

  it('falls back to succeeded/nominated scoring when no transport hint exists', async () => {
    const report = fakeReport([
      nominatedPair,
      realSelectedPair,
      { type: 'local-candidate', id: 'host-l', candidateType: 'host' },
      { type: 'remote-candidate', id: 'host-r', candidateType: 'host' },
      { type: 'local-candidate', id: 'srflx-l', candidateType: 'srflx' },
      { type: 'remote-candidate', id: 'prflx-r', candidateType: 'prflx' }
    ])
    const pair = await samplePair(fakePc(report))
    expect(pair?.source).toBe('fallback-scoring')
    expect(pair?.localCandidateType).toBe('host')
    expect(pair?.remoteCandidateType).toBe('host')
  })
})
