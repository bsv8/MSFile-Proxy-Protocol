export type LogSide = 'browser'

export interface LogRecord {
  time: string
  side: LogSide
  event: string
  [key: string]: unknown
}

const REDACTED_KEYS = ['private_key', 'private_key_hex', 'sdp', 'credential', 'username', 'password']

export function sanitizeRecord(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(record)) {
    if (REDACTED_KEYS.some((k) => key.toLowerCase().includes(k))) {
      out[key] = '[REDACTED]'
      continue
    }
    out[key] = value
  }
  return out
}

export class EventLog {
  readonly records: LogRecord[] = []
  private readonly sink: ((line: string) => void) | undefined

  constructor(sink?: (line: string) => void) {
    this.sink = sink
  }

  emit(event: string, fields: Record<string, unknown> = {}): LogRecord {
    const record: LogRecord = {
      time: new Date().toISOString(),
      side: 'browser',
      event,
      ...fields
    }
    this.records.push(record)
    const line = JSON.stringify(sanitizeRecord(record))
    this.sink?.(line)
    return record
  }

  toJSONL(): string {
    return this.records.map((r) => JSON.stringify(r)).join('\n')
  }
}

export interface DiagInfo {
  isSecureContext: boolean
  userAgent: string
  webRTCAvailable: boolean
  stunList: string
  turnRejections: string[]
}

export function collectDiagnostics(stunInput: string): DiagInfo {
  const webRTCAvailable = typeof window !== 'undefined' &&
    typeof window.RTCPeerConnection === 'function' &&
    typeof RTCSessionDescription === 'function'
  return {
    isSecureContext: typeof window !== 'undefined' ? window.isSecureContext : false,
    userAgent: navigator.userAgent,
    webRTCAvailable,
    stunList: stunInput,
    turnRejections: []
  }
}

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (className != null && className !== '') {
    node.className = className
  }
  return node
}

export function setText(id: string, text: string): void {
  const target = document.getElementById(id)
  if (target != null) {
    target.textContent = text
  }
}

export function inputValue(id: string): string {
  const input = document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement | null
  return input?.value ?? ''
}

export function setInputValue(id: string, value: string): void {
  const input = document.getElementById(id) as HTMLInputElement | HTMLTextAreaElement | null
  if (input != null) {
    input.value = value
  }
}

export function setChecked(id: string, checked: boolean): void {
  const input = document.getElementById(id) as HTMLInputElement | null
  if (input != null) {
    input.checked = checked
  }
}

export function on(id: string, handler: (ev: Event) => void): void {
  document.getElementById(id)?.addEventListener('click', handler)
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function appendLogLine(line: string): void {
  const pane = document.getElementById('log-pane')
  if (pane == null) {
    return
  }
  const lineEl = el('div', 'log-line')
  lineEl.textContent = line
  pane.appendChild(lineEl)
  while (pane.childElementCount > 2000) {
    pane.removeChild(pane.firstChild as ChildNode)
  }
  pane.scrollTop = pane.scrollHeight
}
