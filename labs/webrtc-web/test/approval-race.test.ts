import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import type { Connection, Stream } from '@libp2p/interface'
import { deriveIdentity } from '../src/identity'
import { ApprovalRegistry, serveIfApproved, connInfoOf } from '../src/private'
import { handleIdentityStream } from '../src/protocols'
import type { LabEventHandler, LabServerOptions } from '../src/private'

const vectorPath = fileURLToPath(new URL('../testdata/identity-vector.json', import.meta.url))
const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as { private_key_hex: string }

describe('lab protocol approval timing race (identity arrives before listener approval)', () => {
  const identity = deriveIdentity(vector.private_key_hex)

  interface Harness {
    approvals: ApprovalRegistry
    events: Array<Record<string, unknown>>
    makeExpectedConn: () => Connection
    makeStrangerConn: () => Connection
  }

  function harness(): Harness {
    const approvals = new ApprovalRegistry()
    approvals.setExpectedPeerId(identity.peerId.toString())
    const events: Array<Record<string, unknown>> = []
    let counter = 0
    const make = (remotePeerIdText: string): Connection =>
      ({
        id: `conn-${++counter}`,
        remotePeer: {
          toString: () => remotePeerIdText,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          toMultihash: () => { throw new Error('test stub peer id carries no key material') }
        },
        direct: true,
        limits: null,
        remoteAddr: { toString: () => '/ip4/1.2.3.4/udp/4001/webrtc-direct/certhash/x' }
      }) as unknown as Connection
    return {
      approvals,
      events,
      makeExpectedConn: () => make(identity.peerId.toString()),
      makeStrangerConn: () => make(deriveIdentity('33'.repeat(32)).peerId.toString())
    }
  }

  function fakeStream() {
    const state = {
      abortedReasons: [] as string[],
      sentBytes: 0,
      closed: false
    }
    const stream = {
      writableNeedsDrain: false,
      send(data: Uint8Array): boolean {
        state.sentBytes += data.byteLength
        return true
      },
      close: async (): Promise<void> => {
        state.closed = true
      },
      addEventListener(): void {},
      removeEventListener(): void {},
      abort(err?: Error): void {
        state.abortedReasons.push(String(err?.message ?? 'abort'))
      }
    }
    return { stream: stream as unknown as Stream, state }
  }

  function optionsFor(h: Harness, approvalWaitMs?: number): LabServerOptions {
    const handler: LabEventHandler = (e) => h.events.push(e)
    return {
      node: {} as import('libp2p').Libp2p,
      identity,
      approvals: h.approvals,
      onEvent: handler,
      ...(approvalWaitMs != null ? { approvalWaitMs } : {})
    }
  }

  function firstEvent(events: Array<Record<string, unknown>>, name: string): Record<string, unknown> | undefined {
    return events.find((e) => e['event'] === name)
  }

  it('serves identity that arrives before approval once the expected dialer is approved later', async () => {
    const h = harness()
    const conn = h.makeExpectedConn()
    const { stream, state } = fakeStream()
    let approved = false
    const serving = serveIfApproved(
      'identity',
      stream,
      conn,
      optionsFor(h, 2000),
      () => handleIdentityStream({ stream, info: connInfoOf(conn, identity) })
    )
    setTimeout(() => {
      approved = true
      h.approvals.approve(conn.id, identity.peerId.toString())
    }, 150)
    await serving
    expect(approved).toBe(true)
    expect(state.abortedReasons).toEqual([])
    expect(state.sentBytes).toBeGreaterThan(0)
    expect(firstEvent(h.events, 'lab_protocol_pending_approval')).toBeDefined()
    expect(firstEvent(h.events, 'protocol_served')).toBeDefined()
  })

  it('denies an expected dialer whose approval never arrives within the bounded window', async () => {
    const h = harness()
    const conn = h.makeExpectedConn()
    const { stream, state } = fakeStream()
    await serveIfApproved(
      'identity',
      stream,
      conn,
      optionsFor(h, 300),
      async () => {}
    )
    const denied = firstEvent(h.events, 'lab_protocol_denied')
    expect(denied).toBeDefined()
    expect(String(denied?.['error_code'])).toMatch(/approval timeout/)
    expect(state.abortedReasons).toEqual(['approval timeout'])
    expect(state.sentBytes).toBe(0)
  })

  it('rejects unexpected peers immediately without waiting', async () => {
    const h = harness()
    const conn = h.makeStrangerConn()
    const { stream, state } = fakeStream()
    const started = Date.now()
    await serveIfApproved(
      'identity',
      stream,
      conn,
      optionsFor(h, 5000),
      async () => {}
    )
    const elapsed = Date.now() - started
    expect(elapsed).toBeLessThan(500)
    const denied = firstEvent(h.events, 'lab_protocol_denied')
    expect(String(denied?.['error_code'])).toMatch(/connection not approved/)
    expect(state.abortedReasons).toEqual(['connection not approved'])
    expect(firstEvent(h.events, 'lab_protocol_pending_approval')).toBeUndefined()
  })
})
