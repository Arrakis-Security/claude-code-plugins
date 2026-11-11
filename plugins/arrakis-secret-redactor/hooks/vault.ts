import { secretSpans } from './detect'

// Also matches the untagged `‹SECRET_n›` of earlier versions, so a placeholder from an old transcript is still caught.
export const PLACEHOLDER = /‹SECRET_(?:[a-z0-9]+_)?\d+›/g

// Real values live in this module's memory for the session only: never in $.store, a file or a log.
const looksRandom = (value: string): boolean => value.length >= 8 && /[A-Za-z]/.test(value) && /[0-9]/.test(value)

const MIN_REPLAYED_LENGTH = 6

const randomTag = (): string => Math.floor(Math.random() * 36 ** 8).toString(36).padStart(8, '0')

export class Vault {
  private byValue = new Map<string, string>()
  private byPlaceholder = new Map<string, string>()
  // A plain word caught only by its name stays masked there; replaying it everywhere hid words like "boolean" from every later result.
  private replayable = new Set<string>()
  // Longest first, so a shorter value never splits a longer one and leaves its tail visible.
  private replayOrder: string[] = []

  // Numbering restarts with each process, so the tag keeps a placeholder from an earlier process from naming a different value.
  constructor(private readonly tag: string = randomTag()) {}

  // A short or all-digit piece of a wider match is a fragment such as a year, not the secret.
  private remember(value: string, named: boolean | undefined, isPiece: boolean): void {
    if (named === true && !looksRandom(value)) return
    if (isPiece && (value.length < MIN_REPLAYED_LENGTH || /^\d+$/.test(value))) return
    if (this.replayable.has(value)) return
    this.placeholderOf(value)
    this.replayable.add(value)
    const at = this.replayOrder.findIndex(known => known.length < value.length)
    this.replayOrder.splice(at === -1 ? this.replayOrder.length : at, 0, value)
  }

  private placeholderOf(value: string): string {
    let placeholder = this.byValue.get(value)
    if (placeholder === undefined) {
      placeholder = `‹SECRET_${this.tag}_${this.byValue.size + 1}›`
      this.byValue.set(value, placeholder)
      this.byPlaceholder.set(placeholder, value)
    }
    return placeholder
  }

  knows(placeholder: string): boolean {
    return this.byPlaceholder.has(placeholder)
  }

  // Known values are swapped too, so a secret seen once stays covered where no rule would catch it again.
  mask(text: string): { text: string; count: number } {
    let count = 0
    let out = ''
    let at = 0
    for (const span of secretSpans(text)) {
      out += text.slice(at, span.start) + this.placeholderOf(text.slice(span.start, span.end))
      this.remember(text.slice(span.start, span.end), span.named, false)
      for (const part of span.parts ?? []) this.remember(text.slice(part.start, part.end), part.named, true)
      at = span.end
      count += 1
    }
    out += text.slice(at)
    for (const value of this.replayOrder) {
      const placeholder = this.byValue.get(value)!
      if (out.includes(value)) {
        count += out.split(value).length - 1
        out = out.split(value).join(placeholder)
      }
    }
    return { text: out, count }
  }

  unmask(text: string): string {
    return text.replace(PLACEHOLDER, whole => this.byPlaceholder.get(whole) ?? whole)
  }
}

export function placeholdersIn(text: string): Set<string> {
  return new Set(text.match(PLACEHOLDER) ?? [])
}

export class Refusal extends Error {}

function isPlain(value: object): boolean {
  if (Array.isArray(value)) return true
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

const MEDIA_FIELDS = new Set(['base64', 'data'])
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/
const BASE64_DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const MEDIA_HEADERS = new Map([
  ['image/png', /^\x89PNG\r\n\x1a\n/],
  ['image/jpeg', /^\xff\xd8\xff/],
  ['image/gif', /^GIF8[79]a/],
  ['image/webp', /^RIFF[\s\S]{4}WEBP/],
  ['application/pdf', /^%PDF-/],
])
const MEDIA_TYPE_FIELDS = ['type', 'mimeType', 'media_type', 'mediaType']

function firstBytes(base64: string): string {
  let bits = 0
  let held = 0
  let bytes = ''
  for (const digit of base64.slice(0, 16)) {
    const value = BASE64_DIGITS.indexOf(digit)
    if (value === -1) break
    bits = ((bits << 6) | value) & 0xffff
    held += 6
    if (held >= 8) {
      held -= 8
      bytes += String.fromCharCode((bits >> held) & 0xff)
    }
  }
  return bytes
}

function declaredMedia(record: Record<string, unknown>, fromParent: string | undefined): string | undefined {
  for (const field of MEDIA_TYPE_FIELDS) {
    const type = record[field]
    if (typeof type === 'string' && MEDIA_HEADERS.has(type)) return type
  }
  return fromParent
}

// Masking breaks an image or a PDF; a media field is left whole only when the result declares its type and its bytes start with that type's header.
export function isEncodedMedia(field: string, value: unknown, mediaType: string | undefined): value is string {
  const header = mediaType === undefined ? undefined : MEDIA_HEADERS.get(mediaType)
  return header !== undefined && MEDIA_FIELDS.has(field) && typeof value === 'string' && BASE64.test(value) && header.test(firstBytes(value))
}

// Rebuilds the value with every string masked; a shape it cannot rebuild faithfully is refused, never passed through.
export function maskDeep(value: unknown, vault: Vault, tally: { count: number }, mediaFromParent?: string): unknown {
  if (typeof value === 'string') {
    const masked = vault.mask(value)
    tally.count += masked.count
    return masked.text
  }
  if (value === null || typeof value !== 'object') return value
  if (!isPlain(value)) throw new Refusal('a result shape the redactor cannot rebuild')
  if (Array.isArray(value)) return value.map(item => maskDeep(item, vault, tally))
  const record = value as Record<string, unknown>
  const mediaType = declaredMedia(record, mediaFromParent)
  // Read declares a PDF one level above its bytes: `{ type: 'pdf', file: { base64 } }`.
  const mediaForChildren = record.type === 'pdf' ? 'application/pdf' : undefined
  return Object.fromEntries(
    Object.entries(record).map(([k, v]) => [
      maskDeep(k, vault, tally) as string,
      isEncodedMedia(k, v, mediaType) ? v : maskDeep(v, vault, tally, mediaForChildren),
    ]),
  )
}
