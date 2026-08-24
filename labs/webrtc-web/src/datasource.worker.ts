import { DeterministicBatcher } from './protocols'

export interface DatasourceWorkerRequest {
  type: 'start' | 'digest' | 'ack'
  totalBytes?: string
  seed?: string
}

const INITIAL_CREDITS = 8

let batcher: DeterministicBatcher | undefined
let credits = 0
let pumping = false

function post(msg: Record<string, unknown>, transfer?: Transferable[]): void {
  ;(self as unknown as Worker).postMessage(msg, transfer ?? [])
}

function pump(): void {
  if (pumping || batcher == null || credits <= 0) {
    return
  }
  pumping = true
  try {
    while (credits > 0) {
      const batch = batcher.nextBatch()
      if (batch == null) {
        post({ type: 'done' })
        credits = 0
        return
      }
      credits -= 1
      post({ type: 'batch', data: batch.buffer }, [batch.buffer])
    }
  } finally {
    pumping = false
  }
}

self.onmessage = (evt: MessageEvent<DatasourceWorkerRequest>) => {
  const msg = evt.data
  if (msg.type === 'start') {
    const totalBytes = BigInt(msg.totalBytes ?? '0')
    const seed = BigInt(msg.seed ?? '0')
    batcher = new DeterministicBatcher(totalBytes, seed)
    credits = INITIAL_CREDITS
    pump()
    return
  }
  if (msg.type === 'ack') {
    credits += 1
    pump()
    return
  }
  if (msg.type === 'digest') {
    if (batcher == null) {
      post({ type: 'error', error: 'digest requested before start' })
      return
    }
    post({ type: 'digest', digest: batcher.digestHex() })
  }
}
