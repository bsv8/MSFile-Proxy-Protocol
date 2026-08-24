import { afterEach, describe, expect, it } from 'vitest'
import { installPeerConnectionObserver, samplePair } from '../src/stats'
import type { PeerConnectionObserver } from '../src/stats'

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

interface FakePcOptions {
  id: string
  withSelectedPair: boolean
}

class FakePC {
  connectionState: RTCPeerConnectionState = 'new'

  readonly options: FakePcOptions

  constructor(options: FakePcOptions) {
    this.options = options
  }

  async getStats(): Promise<RTCStatsReport> {
    const stats: FakeStat[] = [
      { type: 'local-candidate', id: 'host-l', candidateType: 'host' },
      { type: 'remote-candidate', id: 'host-r', candidateType: 'host' }
    ]
    if (this.options.withSelectedPair) {
      stats.push({
        type: 'candidate-pair',
        id: `pair-${this.options.id}`,
        state: 'succeeded',
        nominated: true,
        bytesSent: 10,
        bytesReceived: 10,
        localCandidateId: 'host-l',
        remoteCandidateId: 'host-r'
      })
    }
    return fakeReport(stats)
  }
}

let observer: PeerConnectionObserver | undefined

function installWithFakeWindow(): PeerConnectionObserver {
  const existing = globalThis as Record<string, unknown>
  const fakeWindow = {
    RTCPeerConnection: FakePC as unknown as typeof RTCPeerConnection,
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis)
  }
  existing['window'] = fakeWindow
  return installPeerConnectionObserver()
}

afterEach(() => {
  observer?.stop()
  observer = undefined
})

describe('waitForSelectedPair ambiguity detection (issue: second PC without pair yet)', () => {
  it('reports ambiguous when two new PCs exist even if only one has a selected pair', async () => {
    observer = installWithFakeWindow()
    const generationBefore = observer.currentGeneration()
    void new (window.RTCPeerConnection as unknown as new (o?: FakePcOptions) => FakePC)({
      id: 'a',
      withSelectedPair: true
    })
    void new (window.RTCPeerConnection as unknown as new (o?: FakePcOptions) => FakePC)({
      id: 'b',
      withSelectedPair: false
    })

    await expect(observer.waitForSelectedPair(generationBefore, 800, 100)).rejects.toThrow(
      /ambiguous ICE evidence: 2 new PeerConnections.*1 of them already produced/
    )
  }, 5_000)

  it('resolves when exactly one new open PC has a selected pair', async () => {
    observer = installWithFakeWindow()
    const generationBefore = observer.currentGeneration()
    void new (window.RTCPeerConnection as unknown as new (o?: FakePcOptions) => FakePC)({
      id: 'only',
      withSelectedPair: true
    })

    const bound = await observer.waitForSelectedPair(generationBefore, 2000, 100)
    expect(bound.generation).toBe(generationBefore + 1)
    expect(bound.pair.localCandidateType).toBe('host')
    expect(bound.pair.remoteCandidateType).toBe('host')
  }, 5_000)

  it('ignores closed PCs when counting ambiguity', async () => {
    observer = installWithFakeWindow()
    const generationBefore = observer.currentGeneration()

    const first = new (window.RTCPeerConnection as unknown as new (o?: FakePcOptions) => FakePC)({
      id: 'open',
      withSelectedPair: true
    })
    const closedOne = new (window.RTCPeerConnection as unknown as new (o?: FakePcOptions) => FakePC)({
      id: 'closed',
      withSelectedPair: true
    })
    closedOne.connectionState = 'closed' as RTCPeerConnectionState
    void first

    const bound = await observer.waitForSelectedPair(generationBefore, 2000, 100)
    expect(bound.pair.source).toBeDefined()
  }, 5_000)
})

describe('samplePair over fake PCs', () => {
  it('extracts candidate types from a succeeded nominated pair', async () => {
    observer = installWithFakeWindow()
    const pc = new (window.RTCPeerConnection as unknown as new (o?: FakePcOptions) => FakePC)({
      id: 'x',
      withSelectedPair: true
    }) as unknown as RTCPeerConnection
    const pair = await samplePair(pc)
    expect(pair?.state).toBe('succeeded')
    expect(pair?.nominated).toBe(true)
  })
})
