import { sha256 } from '@noble/hashes/sha2.js'

export class IncrementalSha256 {
  private readonly hash = sha256.create()
  private length = 0

  update(data: Uint8Array): void {
    this.hash.update(data)
    this.length += data.byteLength
  }

  digestHex(): string {
    return toHex(this.digest())
  }

  digest(): Uint8Array {
    return this.hash.digest().slice()
  }

  get byteLength(): number {
    return this.length
  }
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0')
  }
  return out
}

export interface TransferStats {
  totalBytes: number
  elapsedMs: number
  ttfbMs: number
  mibPerSecond: number
}

export class ThroughputMeter {
  private startedAt = 0
  private firstByteAt = 0
  private total = 0

  start(): void {
    this.startedAt = performance.now()
  }

  onFirstByte(): void {
    if (this.firstByteAt === 0) {
      this.firstByteAt = performance.now()
    }
  }

  add(bytes: number): void {
    this.total += bytes
  }

  finish(): TransferStats {
    const end = performance.now()
    const elapsedMs = Math.max(end - this.startedAt, 0.001)
    const ttfbMs = this.firstByteAt > 0 ? this.firstByteAt - this.startedAt : 0
    const seconds = elapsedMs / 1000
    return {
      totalBytes: this.total,
      elapsedMs,
      ttfbMs,
      mibPerSecond: this.total / (1024 * 1024) / seconds
    }
  }
}

interface PerformanceWithMemory extends Performance {
  memory?: { usedJSHeapSize: number }
}

function currentHeapBytes(): number | undefined {
  return (performance as PerformanceWithMemory).memory?.usedJSHeapSize
}

export function peakHeapBytes(): number | undefined {
  return currentHeapBytes()
}

export class PeakHeapSampler {
  private timer: ReturnType<typeof setInterval> | undefined
  private baseline: number | undefined
  private maxSeen: number | undefined

  start(): void {
    this.baseline = currentHeapBytes()
    this.maxSeen = this.baseline
    if (this.baseline == null) {
      return
    }
    this.timer = setInterval(() => {
      const now = currentHeapBytes()
      if (now != null && (this.maxSeen == null || now > this.maxSeen)) {
        this.maxSeen = now
      }
    }, 250)
  }

  stopAndDelta(): number | undefined {
    if (this.timer != null) {
      clearInterval(this.timer)
      this.timer = undefined
    }
    const end = currentHeapBytes()
    if (this.baseline == null || end == null || this.maxSeen == null) {
      return undefined
    }
    return Math.max(this.maxSeen, end) - this.baseline
  }
}

export type CandidateType = 'host' | 'srflx' | 'prflx' | 'relay' | 'unknown'

export interface SelectedCandidatePair {
  localCandidateType: CandidateType
  remoteCandidateType: CandidateType
  localCandidateId: string
  remoteCandidateId: string
  bytesSent: number
  bytesReceived: number
  currentRttMs: number | undefined
  state: string
  nominated: boolean
  selected: boolean
  source: 'transport-selected-pair' | 'fallback-scoring'
  sampledAt: string
}

export interface BoundPair {
  pair: SelectedCandidatePair
  generation: number
}

const ALLOWED_TYPES_FOR_TRANSFER: CandidateType[] = ['host', 'srflx', 'prflx']

export function isPairAllowedForTransfer(pair: SelectedCandidatePair | undefined): boolean {
  if (pair == null) {
    return false
  }
  return ALLOWED_TYPES_FOR_TRANSFER.includes(pair.localCandidateType) &&
    ALLOWED_TYPES_FOR_TRANSFER.includes(pair.remoteCandidateType)
}

interface ObserverEntry {
  pc: RTCPeerConnection
  generation: number
  latest: SelectedCandidatePair | undefined
  samples: number
}

export interface PeerConnectionObserver {
  currentGeneration(): number
  list(): ObserverSnapshot[]
  latestFor(pc: RTCPeerConnection): SelectedCandidatePair | undefined
  newestPairSince(generation: number): SelectedCandidatePair | undefined
  sampleNow(): Promise<void>
  refreshGeneration(generation: number): Promise<SelectedCandidatePair | undefined>
  waitForSelectedPair(generation: number, timeoutMs?: number, pollMs?: number): Promise<BoundPair>
  anyRelaySelected(): boolean
  stop(): void
}

export interface ObserverSnapshot {
  generation: number
  label: string
  samples: number
  pair: SelectedCandidatePair | undefined
}

let observer: PeerConnectionObserver | undefined

export function installPeerConnectionObserver(): PeerConnectionObserver {
  if (typeof window === 'undefined' || window.RTCPeerConnection == null) {
    throw new Error('RTCPeerConnection unavailable')
  }
  if (observer != null && isObservedCtor(window.RTCPeerConnection)) {
    return observer
  }
  const NativePC = window.RTCPeerConnection
  const entries = new Map<RTCPeerConnection, ObserverEntry>()
  let counter = 0

  class Observed extends NativePC {
    readonly observerGeneration: number

    constructor(config?: RTCConfiguration) {
      super(config)
      counter += 1
      this.observerGeneration = counter
      entries.set(this, { pc: this, generation: counter, latest: undefined, samples: 0 })
    }
  }

  function isObservedCtor(candidate: unknown): boolean {
    return candidate === Observed
  }

  Object.defineProperty(window, 'RTCPeerConnection', {
    value: Observed,
    writable: true,
    configurable: true
  })

  function findEntry(generation: number): ObserverEntry | undefined {
    for (const e of entries.values()) {
      if (e.generation === generation) {
        return e
      }
    }
    return undefined
  }

  async function sampleEntries(filter: (e: ObserverEntry) => boolean): Promise<void> {
    const targets = [...entries.values()].filter((e) => e.pc.connectionState !== 'closed' && filter(e))
    await Promise.all(targets.map(async (entry) => {
      try {
        const pair = await samplePair(entry.pc)
        entry.samples += 1
        if (pair != null) {
          entry.latest = pair
        }
      } catch {}
    }))
  }

  const timer = window.setInterval(() => {
    void sampleEntries(() => true)
  }, 1000)

  observer = {
    currentGeneration(): number {
      return counter
    },
    list(): ObserverSnapshot[] {
      return [...entries.values()]
        .sort((a, b) => a.generation - b.generation)
        .map((e) => ({ generation: e.generation, label: `pc#${e.generation}`, samples: e.samples, pair: e.latest }))
    },
    latestFor(pc: RTCPeerConnection): SelectedCandidatePair | undefined {
      return entries.get(pc)?.latest
    },
    newestPairSince(generation: number): SelectedCandidatePair | undefined {
      let newestGen = -1
      let newest: SelectedCandidatePair | undefined
      for (const e of entries.values()) {
        if (e.generation <= generation || e.latest == null) {
          continue
        }
        if (e.generation > newestGen) {
          newestGen = e.generation
          newest = e.latest
        }
      }
      return newest
    },
    async sampleNow(): Promise<void> {
      await sampleEntries(() => true)
    },
    async refreshGeneration(generation: number): Promise<SelectedCandidatePair | undefined> {
      await sampleEntries((e) => e.generation === generation)
      return findEntry(generation)?.latest
    },
    async waitForSelectedPair(generation: number, timeoutMs = 20_000, pollMs = 200): Promise<BoundPair> {
      const deadline = Date.now() + timeoutMs
      for (;;) {
        await sampleEntries((e) => e.generation > generation)
        const newOpenEntries = [...entries.values()].filter(
          (e) => e.generation > generation && e.pc.connectionState !== 'closed'
        )
        if (newOpenEntries.length > 1) {
          const gens = newOpenEntries.map((e) => `#${e.generation}${e.latest != null ? '*' : ''}`).join(',')
          const withPairs = newOpenEntries.filter((e) => e.latest != null).length
          throw new Error(
            `ambiguous ICE evidence: ${newOpenEntries.length} new PeerConnections were created since marker (generations ${gens}; ${withPairs} of them already produced a selected pair); cannot bind evidence to a single connection`
          )
        }
        const single = newOpenEntries[0]
        if (single != null && single.latest != null) {
          return { pair: single.latest as SelectedCandidatePair, generation: single.generation }
        }
        if (Date.now() >= deadline) {
          throw new Error(`timed out waiting for a selected ICE candidate pair from a new PeerConnection (generation > ${generation})`)
        }
        await new Promise((resolve) => setTimeout(resolve, pollMs))
      }
    },
    anyRelaySelected(): boolean {
      return [...entries.values()].some((e) => e.latest != null && !isPairAllowedForTransfer(e.latest))
    },
    stop(): void {
      window.clearInterval(timer)
      entries.clear()
      Object.defineProperty(window, 'RTCPeerConnection', {
        value: NativePC,
        writable: true,
        configurable: true
      })
      observer = undefined
    }
  }
  return observer
}

export async function samplePair(pc: RTCPeerConnection): Promise<SelectedCandidatePair | undefined> {
  const report = await pc.getStats()

  let transportSelectedId: string | undefined
  report.forEach((stat) => {
    if (stat.type === 'transport') {
      const tp = stat as RTCStats & { selectedCandidatePairId?: string }
      if (tp.selectedCandidatePairId != null && tp.selectedCandidatePairId !== '') {
        transportSelectedId = tp.selectedCandidatePairId
      }
    }
  })
  if (transportSelectedId != null) {
    const cp = report.get(transportSelectedId) as (RTCIceCandidatePairStats & { selected?: boolean }) | undefined
    if (cp != null) {
      return buildPair(report, cp, 'transport-selected-pair')
    }
  }

  let best: (RTCIceCandidatePairStats & { selected?: boolean }) | undefined
  let bestScore = -1
  report.forEach((stat) => {
    if (stat.type !== 'candidate-pair') {
      return
    }
    const cp = stat as RTCIceCandidatePairStats & { selected?: boolean }
    if (cp.state !== 'succeeded') {
      return
    }
    const score = (cp.selected === true ? 100 : 0) + (cp.nominated === true ? 50 : 0) +
      Number(cp.bytesSent ?? 0) / 1e12 + Number(cp.bytesReceived ?? 0) / 1e12
    if (score <= bestScore) {
      return
    }
    bestScore = score
    best = cp
  })
  if (best == null) {
    return undefined
  }
  return buildPair(report, best, 'fallback-scoring')
}

function buildPair(
  report: RTCStatsReport,
  cp: RTCIceCandidatePairStats & { selected?: boolean },
  source: 'transport-selected-pair' | 'fallback-scoring'
): SelectedCandidatePair {
  return {
    localCandidateType: candidateTypeOf(report, cp.localCandidateId),
    remoteCandidateType: candidateTypeOf(report, cp.remoteCandidateId),
    localCandidateId: cp.localCandidateId ?? '',
    remoteCandidateId: cp.remoteCandidateId ?? '',
    bytesSent: Number(cp.bytesSent ?? 0),
    bytesReceived: Number(cp.bytesReceived ?? 0),
    currentRttMs: cp.currentRoundTripTime != null ? cp.currentRoundTripTime * 1000 : undefined,
    state: cp.state ?? 'unknown',
    nominated: cp.nominated === true,
    selected: cp.selected === true,
    source,
    sampledAt: new Date().toISOString()
  }
}

interface MinimalIceCandidateStats {
  candidateType?: string
}

function candidateTypeOf(report: RTCStatsReport, candidateId: string | undefined): CandidateType {
  if (candidateId == null || candidateId === '') {
    return 'unknown'
  }
  const stat = report.get(candidateId) as Partial<MinimalIceCandidateStats> | undefined
  const t = stat?.candidateType as CandidateType | undefined
  if (t === 'host' || t === 'srflx' || t === 'prflx' || t === 'relay') {
    return t
  }
  return 'unknown'
}
