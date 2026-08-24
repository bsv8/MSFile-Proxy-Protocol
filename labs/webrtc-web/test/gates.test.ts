import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { parseIceServersInput, assertNoTurnInRtcConfiguration } from '../src/node'
import { evaluateDirectGate } from '../src/direct'
import { isPairAllowedForTransfer } from '../src/stats'
import { deriveIdentity } from '../src/identity'
import type { Connection } from '@libp2p/interface'
import type { SelectedCandidatePair } from '../src/stats'

const vectorPath = fileURLToPath(new URL('../testdata/identity-vector.json', import.meta.url))
const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
  private_key_hex: string
  public_key_hex: string
}

function fakeConnection(remotePeerId: string, opts: { direct?: boolean; limits?: Record<string, unknown> }): Connection {
  return {
    remotePeer: peerIdFromStringShim(remotePeerId),
    direct: opts.direct ?? true,
    limits: opts.limits,
    remoteAddr: { toString: () => '/ip4/1.2.3.4/udp/4001/webrtc-direct/certhash/x' },
    streams: [],
    id: 'test-conn',
    direction: 'outbound',
    status: 'open',
    timeline: {},
    log: {}
  } as unknown as Connection
}

function peerIdFromStringShim(text: string): unknown {
  return { toString: () => text }
}

function pair(localType: string, remoteType: string): SelectedCandidatePair | undefined {
  return {
    localCandidateType: localType as SelectedCandidatePair['localCandidateType'],
    remoteCandidateType: remoteType as SelectedCandidatePair['remoteCandidateType'],
    localCandidateId: 'l',
    remoteCandidateId: 'r',
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

describe('TURN hard rejection (T10)', () => {
  it('accepts stun urls only', () => {
    const parsed = parseIceServersInput('stun:stun.example.com:3478')
    expect(parsed.turnRejected).toBe(false)
    expect(parsed.iceServers).toHaveLength(1)
    expect(parsed.rejected).toHaveLength(0)
  })

  it('rejects turn: and turns: urls before startup', () => {
    for (const url of ['turn:turn.example.com:3478', 'turns:turn.example.com:5349']) {
      const parsed = parseIceServersInput(`stun:stun.example.com\n${url}`)
      expect(parsed.turnRejected).toBe(true)
      expect(parsed.iceServers).toHaveLength(1)
      expect(parsed.rejected[0]).toBe(url)
    }
  })

  it('strips turn credentials from RTCConfiguration json', () => {
    let threw = false
    try {
      assertNoTurnInRtcConfiguration(JSON.stringify({
        iceTransportPolicy: 'relay',
        iceServers: [{ urls: ['turn:t.example'], username: 'u', credential: 'p' }]
      }))
    } catch (err) {
      threw = true
      expect((err as Error).message).toContain('relay')
    }
    expect(threw).toBe(true)
  })

  it('rejects turn urls embedded in RTCConfiguration json', () => {
    expect(() =>
      assertNoTurnInRtcConfiguration(JSON.stringify({ iceServers: [{ urls: ['stun:s.example', 'turn:t.example'] }] }))
    ).toThrow(/turn:t\.example/)
    expect(() =>
      assertNoTurnInRtcConfiguration('{not json')
    ).toThrow(/JSON/)
  })
})

describe('selected candidate type gate (T11)', () => {
  it('allows host/srflx/prflx pairs', () => {
    for (const t of ['host', 'srflx', 'prflx']) {
      expect(isPairAllowedForTransfer(pair(t, t))).toBe(true)
    }
    expect(isPairAllowedForTransfer(undefined)).toBe(false)
  })

  it('blocks relay candidates on either side', () => {
    expect(isPairAllowedForTransfer(pair('relay', 'host'))).toBe(false)
    expect(isPairAllowedForTransfer(pair('host', 'relay'))).toBe(false)
  })
})

describe('direct gate (T02/T13)', () => {
  const derived = deriveIdentity(vector.private_key_hex)

  function connFor(peerIdText: string, opts: { direct?: boolean; limits?: Record<string, unknown> }): Connection {
    return fakeConnection(peerIdText, opts)
  }

  it('passes when identity, direct flag, limits and candidate pair are all clean', () => {
    const gate = evaluateDirectGate({
      conn: connFor(derived.peerId.toString(), { direct: true }),
      expectedPublicKeyHex: derived.publicKeyHex,
      selectedPair: pair('srflx', 'prflx')
    })
    expect(gate.ok).toBe(true)
    expect(gate.failures).toHaveLength(0)
    expect(gate.expectedPeerId).toBe(derived.peerId.toString())
  })

  it('fails on pinned public key mismatch (T13)', () => {
    const other = deriveIdentity('11'.repeat(32))
    const gate = evaluateDirectGate({
      conn: connFor(other.peerId.toString(), { direct: true }),
      expectedPublicKeyHex: derived.publicKeyHex,
      selectedPair: pair('host', 'host')
    })
    expect(gate.ok).toBe(false)
    expect(gate.failures.some((f) => f.includes('mismatch'))).toBe(true)
  })

  it('fails when connection is not direct or has limits', () => {
    const gated = evaluateDirectGate({
      conn: connFor(derived.peerId.toString(), { direct: false }),
      expectedPublicKeyHex: derived.publicKeyHex,
      selectedPair: pair('host', 'host')
    })
    expect(gated.ok).toBe(false)
    expect(gated.failures.some((f) => f.includes('not direct'))).toBe(true)

    const limited = evaluateDirectGate({
      conn: connFor(derived.peerId.toString(), { direct: true, limits: { bytes: 1n } }),
      expectedPublicKeyHex: derived.publicKeyHex,
      selectedPair: pair('host', 'host')
    })
    expect(limited.ok).toBe(false)
    expect(limited.failures.some((f) => f.includes('limits'))).toBe(true)
  })

  it('blocks relay candidate pairs inside the gate (T11)', () => {
    const gate = evaluateDirectGate({
      conn: connFor(derived.peerId.toString(), { direct: true }),
      expectedPublicKeyHex: derived.publicKeyHex,
      selectedPair: pair('host', 'relay')
    })
    expect(gate.ok).toBe(false)
    expect(gate.failures.some((f) => f.includes('relay'))).toBe(true)
  })

  it('requires an observed candidate pair', () => {
    const gate = evaluateDirectGate({
      conn: connFor(derived.peerId.toString(), { direct: true }),
      expectedPublicKeyHex: derived.publicKeyHex
    })
    expect(gate.ok).toBe(false)
    expect(gate.failures.some((f) => f.includes('candidate pair'))).toBe(true)
  })

  it('rejects malformed pinned keys', () => {
    const gate = evaluateDirectGate({
      conn: connFor(derived.peerId.toString(), { direct: true }),
      expectedPublicKeyHex: 'zz',
      selectedPair: pair('host', 'host')
    })
    expect(gate.ok).toBe(false)
    expect(gate.failures.some((f) => f.includes('invalid pinned public key'))).toBe(true)
  })
})
