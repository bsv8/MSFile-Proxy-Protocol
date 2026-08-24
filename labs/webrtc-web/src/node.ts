import { createLibp2p, type Libp2p } from 'libp2p'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { webRTC, webRTCDirect } from '@libp2p/webrtc'
import { webSockets } from '@libp2p/websockets'
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2'
import { identify } from '@libp2p/identify'
import { ping } from '@libp2p/ping'
import { multiaddr, type Multiaddr } from '@multiformats/multiaddr'
import { deriveIdentity, normalizePrivateKeyHex, type LabIdentity } from './identity'
import type { PrivateKey, PeerId } from '@libp2p/interface'

type PeerIdLike = PeerId | Multiaddr | string

export interface IceServerConfig {
  urls: string[]
}

export interface ParsedIceConfig {
  iceServers: RTCIceServer[]
  rejected: string[]
  turnRejected: boolean
}

export const DEFAULT_STUN_INPUT = 'stun:stun.l.google.com:19302'

const TURN_URL_RE = /^turns?:/i

export function parseIceServersInput(input: string): ParsedIceConfig {
  const rejected: string[] = []
  const iceServers: RTCIceServer[] = []
  let turnRejected = false
  for (const rawLine of input.split(/[\n,]/)) {
    const line = rawLine.trim()
    if (line === '') {
      continue
    }
    if (TURN_URL_RE.test(line)) {
      rejected.push(line)
      turnRejected = true
      continue
    }
    if (!/^stun:/i.test(line)) {
      rejected.push(line)
      continue
    }
    iceServers.push({ urls: [line] })
  }
  return { iceServers, rejected, turnRejected }
}

export function assertNoTurnInRtcConfiguration(configJson: string): void {
  let parsed: unknown
  try {
    parsed = JSON.parse(configJson)
  } catch {
    throw new Error('RTCConfiguration is not valid JSON')
  }
  if (parsed == null || typeof parsed !== 'object') {
    return
  }
  const obj = parsed as Record<string, unknown>
  if ('iceTransportPolicy' in obj && String(obj['iceTransportPolicy']).toLowerCase() === 'relay') {
    throw new Error('TURN rejected: iceTransportPolicy "relay" is forbidden in this lab')
  }
  for (const key of ['username', 'credential', 'credentialType']) {
    delete obj[key]
  }
  const servers = obj['iceServers']
  if (Array.isArray(servers)) {
    for (const server of servers) {
      if (server != null && typeof server === 'object' && Array.isArray((server as Record<string, unknown>)['urls'])) {
        for (const url of (server as Record<string, unknown>)['urls'] as unknown[]) {
          if (typeof url === 'string' && TURN_URL_RE.test(url)) {
            throw new Error(`TURN rejected: ${url}`)
          }
        }
      }
    }
  }
}

export type NodeRole = 'direct-dialer' | 'private-listener' | 'private-dialer'

export interface CreateNodeOptions {
  identity: LabIdentity
  role: NodeRole
  stunInput?: string
}

export interface LabNodeServices {
  identify: unknown
  ping: unknown
}

export async function createNode(options: CreateNodeOptions): Promise<Libp2p<{ identify: unknown; ping: { ping(peer: PeerIdLike, options?: { signal?: AbortSignal }): Promise<number> } }>> {
  const privateKey = options.identity.privateKey as PrivateKey
  const listenAddrs = listenAddressesForRole(options.role)
  const stunInput = options.stunInput ?? DEFAULT_STUN_INPUT
  const parsedIce = parseIceServersInput(stunInput)
  if (parsedIce.turnRejected) {
    throw new Error('TURN configuration detected - this lab only allows stun:')
  }
  const rtcConfiguration: RTCConfiguration = {
    iceServers: parsedIce.iceServers,
    iceTransportPolicy: 'all'
  }
  const node = await createLibp2p({
    privateKey,
    addresses: {
      listen: listenAddrs
    },
    transports: [
      webSockets(),
      circuitRelayTransport(),
      webRTC({ rtcConfiguration }),
      webRTCDirect()
    ],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    connectionGater: {
      denyDialMultiaddr: () => false
    },
    services: {
      identify: identify(),
      ping: ping()
    }
  })
  return node as unknown as Libp2p<{ identify: unknown; ping: { ping(peer: PeerIdLike, options?: { signal?: AbortSignal }): Promise<number> } }>
}

function listenAddressesForRole(role: NodeRole): string[] {
  switch (role) {
    case 'private-listener':
      return ['/p2p-circuit', '/webrtc']
    case 'private-dialer':
    case 'direct-dialer':
    default:
      return []
  }
}

export function parseTargetMultiaddr(text: string): Multiaddr {
  const trimmed = text.trim()
  if (trimmed === '') {
    throw new Error('multiaddr must not be empty')
  }
  try {
    return multiaddr(trimmed)
  } catch (err) {
    throw new Error(`invalid multiaddr: ${trimmed}`, { cause: err })
  }
}
