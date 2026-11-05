import { expect, test } from 'claude-code/testing'
import { Vault, maskDeep } from './vault'

// Synthetic values built at run time, so no secret-shaped literal sits in the file.
const RANDOM = ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')

const DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

// A whole number of 3-byte groups, so the text needs no padding.
function toBase64(bytes: Uint8Array): string {
  let text = ''
  for (let i = 0; i < bytes.length; i += 3) {
    const group = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!
    text += [18, 12, 6, 0].map(shift => DIGITS[(group >> shift) & 63]).join('')
  }
  return text
}

// A file header followed by noise, the way a real image or PDF looks to the detector.
function encoded(header: number[] | string): string {
  const head = typeof header === 'string' ? [...header].map(c => c.charCodeAt(0)) : header
  const bytes = new Uint8Array(Math.ceil((head.length + 3000) / 3) * 3)
  bytes.set(head)
  let x = 2463534242
  for (let i = head.length; i < bytes.length; i++) {
    x ^= x << 13
    x ^= x >>> 17
    x ^= x << 5
    bytes[i] = x & 0xff
  }
  return toBase64(bytes)
}

const PNG = encoded([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
const JPEG = encoded([0xff, 0xd8, 0xff, 0xe0])
const GIF = encoded('GIF89a')
const WEBP = encoded('RIFF\x10\x27\x00\x00WEBPVP8 ')
const PDF = encoded('%PDF-1.7\n')

function run(value: unknown): { result: unknown; count: number } {
  const tally = { count: 0 }
  return { result: maskDeep(value, new Vault('t'), tally), count: tally.count }
}

test('the same bytes count as secrets outside a media field', () => {
  for (const bytes of [PNG, JPEG, GIF, WEBP, PDF]) expect(run({ stdout: bytes }).count).toBeGreaterThan(0)
})

test('leaves the bytes of an image or a PDF that Claude reads', () => {
  const results = [
    { type: 'image', file: { base64: PNG, type: 'image/png', originalSize: 3008 } },
    { type: 'image', file: { base64: JPEG, type: 'image/jpeg', originalSize: 3004 } },
    { type: 'image', file: { base64: GIF, type: 'image/gif', originalSize: 3006 } },
    { type: 'image', file: { base64: WEBP, type: 'image/webp', originalSize: 3016 } },
    { type: 'pdf', file: { filePath: '/docs/guide.pdf', base64: PDF, originalSize: 3009 } },
    { type: 'parts', file: { filePath: '/docs/guide.pdf', count: 1 }, pages: [{ base64: PNG, mediaType: 'image/png' }] },
    { content: [{ type: 'image', data: JPEG, mimeType: 'image/jpeg' }] },
    { seen: [{ text: 'chart', images: [{ media_type: 'image/png', data: PNG }] }] },
  ]
  for (const value of results) expect(run(value)).toEqual({ result: value, count: 0 })
})

test('still masks the text fields beside the bytes', () => {
  const { result, count } = run({ type: 'pdf', file: { filePath: `/docs/${RANDOM}.pdf`, base64: PDF } })
  expect(JSON.stringify(result)).not.toContain(RANDOM)
  expect((result as { file: { base64: string } }).file.base64).toBe(PDF)
  expect(count).toBe(1)
})

test('masks media bytes the result does not declare as that type', () => {
  const undeclared = [
    { data: PNG },
    { base64: PDF },
    { type: 'image', data: PNG, mimeType: 'image/jpeg' },
    { data: PDF, mimeType: 'text/plain' },
    { data: JPEG, mimeType: 'constructor' },
    { file: { base64: PDF } },
    { type: 'pdf', pages: [{ base64: PDF }] },
  ]
  for (const value of undeclared) expect(run(value).count).toBeGreaterThan(0)
})

// The accepted limit: a declared PDF reaches Claude whole, including any text inside it.
test('passes a declared PDF whole, text inside it included', () => {
  const pdf = encoded(`%PDF-1.7\nAPI_KEY=${RANDOM}\n`)
  const value = { type: 'pdf', file: { filePath: '/docs/guide.pdf', base64: pdf } }
  expect(run(value)).toEqual({ result: value, count: 0 })
})

test('masks a media field whose value is not an image or a PDF', () => {
  const notMedia = [
    { base64: RANDOM },
    { data: RANDOM },
    { data: `DB_PASSWORD=${RANDOM}` },
    { data: { password: RANDOM } },
    // A file header followed by text that is not base64.
    { base64: `${PNG.slice(0, 40)} password=${RANDOM}` },
    { data: `${PDF.slice(0, 40)}\n${RANDOM}` },
  ]
  for (const value of notMedia) expect(JSON.stringify(run(value).result)).not.toContain(RANDOM)
})
