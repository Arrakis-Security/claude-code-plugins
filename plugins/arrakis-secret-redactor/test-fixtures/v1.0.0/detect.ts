// Detection rules adapted from secrets-veil (MIT, github.com/yonatangross/orchestkit, mods/secrets-veil).

// `named`: only a rule that reads the text around it caught it (a name, or a URL's user part for a plain word), so that text is the evidence, not the value.
export type Span = { start: number; end: number; named?: boolean }

const ENTROPY_MIN_LENGTH = 20
// Hex (git shas, hashes) tops out at 4.0 bits per character and a UUID at 4.09, so neither can cross 4.3.
const ENTROPY_THRESHOLD = 4.3
// "=" counts only as base64 padding at the end, so `KEY=value` scores the value alone.
const TOKEN_RUN = /[A-Za-z0-9+/_-]{20,}={0,2}/g

const VENDOR_SHAPES: readonly RegExp[] = [
  /sk-ant-[A-Za-z0-9_-]{20,}/g,
  /\bsk-[A-Za-z0-9_-]{20,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/g,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/g,
  /\b[sr]k_live_[A-Za-z0-9]{16,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bops_[A-Za-z0-9_-]{20,}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
]

// The secret is group 2: `DB_PASSWORD=hunter22`, `"clientSecret": "abc"`, `api_key: abc`.
const NAMED_VALUE =
  /(\b[A-Za-z0-9_]{0,64}(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)[A-Za-z0-9_]{0,64}["']?\s*[=:]\s*["']?)([^\s"'`,;#]{6,})/gi

// A type, a literal or a pointer to where the value lives is not the value: `credentialsValid: boolean`, `key = process.env.KEY`.
const NOT_A_SECRET_VALUE = /^(?:(?:boolean|string|number|bigint|object|unknown|any|void|never|null|undefined|true|false)\b|\$\{?[A-Za-z_]|process\.env\.|os\.environ|var\.|local\.)/i

// Random by design and never a credential: a tool call's id, and a log or trace id under its own key.
const RANDOM_ID = /\b(?:srv)?toolu_[A-Za-z0-9]{20,}|\b(?:event_id|trace_id|span_id|tool_use_id|request_id)["']?\s*[:=]\s*["']?[A-Za-z0-9_+/=-]+/g

// The password in `postgres://user:PASSWORD@host`.
const URL_PASSWORD = /(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)([^\s@/]{3,})(@)/gi

const BEARER = /(\bBearer\s+)([A-Za-z0-9._~+/=-]{20,})/g

export function shannonEntropy(token: string): number {
  const freq = new Map<string, number>()
  for (const ch of token) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let bits = 0
  for (const count of freq.values()) {
    const p = count / token.length
    bits -= p * Math.log2(p)
  }
  return bits
}

// Paths and kebab names are made of words; random tokens are not, so a run splits on "/", "-", "_" and "+" only when every part reads as a word.
function isWordLike(part: string): boolean {
  if (part.length === 0) return true
  if (/^[a-z]+$|^[A-Z]+$|^[0-9]+$/.test(part)) return true
  const chunks = part.match(/[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+/g) ?? []
  return chunks.join('') === part && part.length / chunks.length >= 3
}

function highEntropySpans(text: string): Span[] {
  const spans: Span[] = []
  for (const m of text.matchAll(TOKEN_RUN)) {
    const run = m[0]
    if (/^sha(1|256|384|512)-/.test(run)) continue
    const parts = run.replace(/=+$/, '').split(/[/_+-]/)
    // A run with no word in it is one token (base64url keys hold "-" and "_"); a run with words scores each odd part alone.
    if (!parts.some(p => p.length > 0 && isWordLike(p))) {
      if (shannonEntropy(run) >= ENTROPY_THRESHOLD) spans.push({ start: m.index!, end: m.index! + run.length })
      continue
    }
    let at = 0
    for (const part of parts) {
      const start = m.index! + run.indexOf(part, at)
      at = start - m.index! + part.length
      if (!isWordLike(part) && part.length >= ENTROPY_MIN_LENGTH && shannonEntropy(part) >= ENTROPY_THRESHOLD) {
        spans.push({ start, end: start + part.length })
      }
    }
  }
  return spans
}

function groupSpans(text: string, pattern: RegExp): Span[] {
  return [...text.matchAll(pattern)].map(m => {
    const start = m.index! + m[1]!.length
    // A letters-only URL password is a word like "postgres"; one with a digit or symbol is a real password, masked everywhere.
    const isPlainWord = pattern === URL_PASSWORD && /^[A-Za-z]+$/.test(m[2]!)
    return { start, end: start + m[2]!.length, named: pattern === NAMED_VALUE || isPlainWord }
  })
}

function wholeSpans(text: string, pattern: RegExp): Span[] {
  return [...text.matchAll(pattern)].map(m => ({ start: m.index!, end: m.index! + m[0].length }))
}

function withoutRandomIds(text: string, spans: Span[]): Span[] {
  const ids = wholeSpans(text, RANDOM_ID)
  return spans.filter(s => !ids.some(id => s.start >= id.start && s.end <= id.end))
}

function union(spans: Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start)
  const merged: Span[] = []
  for (const s of sorted) {
    const last = merged.at(-1)
    if (last && s.start <= last.end) {
      last.end = Math.max(last.end, s.end)
      last.named = last.named === true && s.named === true
    } else merged.push({ ...s })
  }
  return merged
}

// `/body/flags` closed on its own line and followed only by `;`, `,`, `)` or the line end.
const REGEX_LITERAL = /^\/((?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n[])+)\/([dgimsuvy]*)(?=\s*(?:[;,)\]}]|$))/m
// A password can hold any character, so a value counts as a pattern only when it also uses regex syntax a typed secret would not.
const REGEX_SYNTAX = /\\[bdswBDSW]|\[[^\]]*-[^\]]*\]|\(\?[:=!<]|\{\d+,?\d*\}|^\^|\$$/

// `const TOKEN_RUN = /…/g` names a token but holds a pattern that matches one.
function isRegexLiteral(text: string, start: number): boolean {
  const m = REGEX_LITERAL.exec(text.slice(start, text.indexOf('\n', start) === -1 ? undefined : text.indexOf('\n', start)))
  if (!m || !REGEX_SYNTAX.test(m[1]!)) return false
  try {
    new RegExp(m[1]!, m[2])
    return true
  } catch {
    return false
  }
}

export function secretSpans(text: string): Span[] {
  return union([
    ...VENDOR_SHAPES.flatMap(p => wholeSpans(text, p)),
    ...groupSpans(text, NAMED_VALUE).filter(s => !NOT_A_SECRET_VALUE.test(text.slice(s.start, s.end)) && !isRegexLiteral(text, s.start)),
    ...groupSpans(text, URL_PASSWORD),
    ...groupSpans(text, BEARER),
    ...withoutRandomIds(text, highEntropySpans(text)),
  ])
}
