import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { deriveIdentity, isTestPrivateKeyHex, normalizePrivateKeyHex, randomPrivateKeyHex, fillRandom, MAX_RANDOM_FILL_CHUNK, fromHex, toHex } from '../src/identity'
import { peerIdFromCompressedPublicKeyHex } from '../src/direct'

const vectorPath = fileURLToPath(new URL('../testdata/identity-vector.json', import.meta.url))
const vector = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
  name: string
  private_key_hex: string
  public_key_hex: string
  peer_id: string
}

describe('fixed identity vector (T01)', () => {
  it('derives the exact committed compressed public key from private_key_hex', () => {
    const derived = deriveIdentity(vector.private_key_hex)
    expect(derived.publicKeyHex).toBe(vector.public_key_hex.toLowerCase())
    expect(derived.publicKeyHex).toHaveLength(66)
    const raw = fromHex(derived.publicKeyHex)
    expect(raw.length).toBe(33)
    expect(raw[0] === 0x02 || raw[0] === 0x03).toBe(true)
  })

  it('derives the exact committed PeerId from private_key_hex', () => {
    const derived = deriveIdentity(vector.private_key_hex)
    expect(derived.peerId.toString()).toBe(vector.peer_id)
  })

  it('PeerId pin derivation matches identity derivation for the same key', () => {
    const derived = deriveIdentity(vector.private_key_hex)
    const pinned = peerIdFromCompressedPublicKeyHex(derived.publicKeyHex)
    expect(pinned.toString()).toBe(vector.peer_id)
    expect(pinned.equals(derived.peerId)).toBe(true)
  })

  it('uses a secp256k1 peer id (identity multihash embedded key)', () => {
    const derived = deriveIdentity(vector.private_key_hex)
    expect(derived.privateKey.type).toBe('secp256k1')
    expect(vector.peer_id.startsWith('16Uiu2')).toBe(true)
  })
})

describe('private key format and range', () => {
  it('accepts exactly 64 hex characters', () => {
    expect(isTestPrivateKeyHex('00'.repeat(32))).toBe(true)
    expect(isTestPrivateKeyHex('00'.repeat(31))).toBe(false)
    expect(isTestPrivateKeyHex('zz'.repeat(32))).toBe(false)
    expect(isTestPrivateKeyHex(` ${'ab'.repeat(32)} `)).toBe(true)
  })

  it('normalizes to lowercase trimmed hex', () => {
    expect(normalizePrivateKeyHex(` ${'ABCD'.repeat(16)} `)).toBe('abcd'.repeat(16))
    expect(() => normalizePrivateKeyHex('nothex')).toThrow(/64 hex/)
  })

  it('rejects the zero scalar as an identity', () => {
    expect(() => deriveIdentity('00'.repeat(32))).toThrow(/zero/)
  })

  it('generates random keys that derive valid identities', () => {
    for (let i = 0; i < 5; i++) {
      const hex = randomPrivateKeyHex()
      expect(hex).toHaveLength(64)
      const derived = deriveIdentity(hex)
      expect(derived.publicKeyHex).toHaveLength(66)
      expect(derived.peerId.toString()).toMatch(/^16Uiu2/)
    }
  })
})

describe('hex helpers', () => {
  it('roundtrips bytes through hex', () => {
    const bytes = new Uint8Array([0, 1, 254, 255])
    expect(fromHex(toHex(bytes))).toEqual(bytes)
  })
})

describe('fillRandom (issue 1: getRandomValues 64 KiB quota)', () => {
  it('fills payloads larger than the browser single-call limit', () => {
    for (const size of [0, 1, MAX_RANDOM_FILL_CHUNK - 1, MAX_RANDOM_FILL_CHUNK, MAX_RANDOM_FILL_CHUNK + 1, 262144]) {
      const payload = new Uint8Array(size)
      expect(() => fillRandom(payload)).not.toThrow()
      if (size >= MAX_RANDOM_FILL_CHUNK) {
        const seen = new Set<number>()
        for (const b of payload) {
          seen.add(b)
          if (seen.size > 16) break
        }
        expect(seen.size).toBeGreaterThan(16)
      }
    }
  })
})
