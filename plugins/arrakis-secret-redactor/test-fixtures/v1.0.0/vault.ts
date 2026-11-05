import { secretSpans } from './detect'

// Also matches the untagged `‹SECRET_n›` of earlier versions, so a placeholder from an old transcript is still caught.
export const PLACEHOLDER = /‹SECRET_(?:[a-z0-9]+_)?\d+›/g

// Real values live in this module's memory for the session only: never in $.store, a file or a log.
const looksRandom = (value: string): boolean => value.length >= 8 && /[A-Za-z]/.test(value) && /[0-9]/.test(value)

const randomTag = (): string => Math.floor(Math.random() * 36 ** 8).toString(36).padStart(8, '0')

export class Vault {
  private byValue = new Map<string, string>()
  private byPlaceholder = new Map<string, string>()
  // A plain word caught only by its name stays masked there; replaying it everywhere hid words like "boolean" from every later result.
  private replayable = new Set<string>()

  // Numbering restarts with each process, so the tag keeps a placeholder from an earlier process from naming a different value.
  constructor(private readonly tag: string = randomTag()) {}

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
      const value = text.slice(span.start, span.end)
      if (span.named !== true || looksRandom(value)) this.replayable.add(value)
      at = span.end
      count += 1
    }
    out += text.slice(at)
    for (const [value, placeholder] of this.byValue) {
      if (!this.replayable.has(value)) continue
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

// Rebuilds the value with every string masked; a shape it cannot rebuild faithfully is refused, never passed through.
export function maskDeep(value: unknown, vault: Vault, tally: { count: number }): unknown {
  if (typeof value === 'string') {
    const masked = vault.mask(value)
    tally.count += masked.count
    return masked.text
  }
  if (value === null || typeof value !== 'object') return value
  if (!isPlain(value)) throw new Refusal('a result shape the redactor cannot rebuild')
  if (Array.isArray(value)) return value.map(item => maskDeep(item, vault, tally))
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [maskDeep(k, vault, tally) as string, maskDeep(v, vault, tally)]))
}
