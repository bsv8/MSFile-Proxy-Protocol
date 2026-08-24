import { privateKeyFromRaw } from '@libp2p/crypto/keys'
import { peerIdFromPrivateKey } from '@libp2p/peer-id'
import type { PeerId, PrivateKey } from '@libp2p/interface'

export interface LabIdentity {
  privateKey: PrivateKey
  publicKeyHex: string
  peerId: PeerId
}

const HEX_RE = /^[0-9a-fA-F]{64}$/

export function isTestPrivateKeyHex(input: string): boolean {
  return HEX_RE.test(input.trim())
}

export function normalizePrivateKeyHex(input: string): string {
  const trimmed = input.trim().toLowerCase()
  if (!HEX_RE.test(trimmed)) {
    throw new Error('private key must be exactly 64 hex characters (32 bytes)')
  }
  return trimmed
}

export function randomPrivateKeyHex(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  let scalar = BigInt('0x' + toHex(bytes))
  const curveOrder = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141')
  while (scalar === 0n || scalar >= curveOrder) {
    crypto.getRandomValues(bytes)
    scalar = BigInt('0x' + toHex(bytes))
  }
  return scalar.toString(16).padStart(64, '0')
}

export function deriveIdentity(privateKeyHex: string): LabIdentity {
  const normalized = normalizePrivateKeyHex(privateKeyHex)
  const raw = fromHex(normalized)
  if (isAllZero(raw)) {
    throw new Error('private key scalar must not be zero')
  }
  const privateKey = privateKeyFromRaw(raw)
  if (privateKey.type !== 'secp256k1') {
    throw new Error(`expected secp256k1 identity key, got ${privateKey.type}`)
  }
  const publicKeyBytes = privateKey.publicKey.raw
  if (publicKeyBytes.length !== 33) {
    throw new Error(`expected 33-byte compressed public key, got ${publicKeyBytes.length} bytes`)
  }
  const peerId = peerIdFromPrivateKey(privateKey)
  return {
    privateKey,
    publicKeyHex: toHex(publicKeyBytes),
    peerId
  }
}

function isAllZero(bytes: Uint8Array): boolean {
  return bytes.every((b) => b === 0)
}

export function toHex(bytes: Uint8Array): string {
  let out = ''
  for (const b of bytes) {
    out += b.toString(16).padStart(2, '0')
  }
  return out
}

export function fromHex(hex: string): Uint8Array {
  const clean = hex.trim()
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new Error('invalid hex string')
  }
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

export const MAX_RANDOM_FILL_CHUNK = 65536

export function fillRandom(bytes: Uint8Array): void {
  for (let offset = 0; offset < bytes.byteLength; offset += MAX_RANDOM_FILL_CHUNK) {
    const end = Math.min(offset + MAX_RANDOM_FILL_CHUNK, bytes.byteLength)
    crypto.getRandomValues(bytes.subarray(offset, end))
  }
}
