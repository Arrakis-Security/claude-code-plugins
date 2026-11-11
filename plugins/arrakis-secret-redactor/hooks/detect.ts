// Detection rules adapted from secrets-veil (MIT, github.com/yonatangross/orchestkit, mods/secrets-veil).

// `named`: only a rule that reads the text around it caught it (a name, or a URL's user part for a plain word), so that text is the evidence, not the value.
// `parts`: the spans a wider one absorbed, so each value a rule found alone is still hidden again later.
export type Span = { start: number; end: number; named?: boolean; parts?: Span[] }

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

const SECRET_NAMES = String.raw`[A-Za-z0-9_]{0,64}(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)[A-Za-z0-9_]{0,64}`
const MIN_NAMED_VALUE = 6
const MIN_URL_PASSWORD = 3

// The secret is group 2: `DB_PASSWORD=hunter22`, `"clientSecret": "abc"`, `api_key: abc`.
const NAMED_VALUE = new RegExp(String.raw`(\b${SECRET_NAMES}["']?\s*[=:]\s*["']?)([^\s"'\`,;#]{${MIN_NAMED_VALUE},})`, 'gi')

// A type, a literal or a pointer to where the value lives is not the value: `credentialsValid: boolean`, `key = process.env.KEY`.
const TYPE_WORDS = 'boolean|string|number|bigint|object|unknown|any|void|never|null|undefined|true|false'
const POINTERS = String.raw`process\.env\.|os\.environ|var\.|local\.`
const NOT_A_SECRET_VALUE = new RegExp(String.raw`^(?:(?:${TYPE_WORDS})\b|\$\{?[A-Za-z_]|${POINTERS})`, 'i')
// Inside quotes only the whole value is a type, literal or variable: `"string"` and `"${TOKEN}"` are, `"$uperman1!"` and`"null&Void#2024x"` are passwords.
const NOT_A_QUOTED_SECRET = new RegExp(String.raw`^(?:(?:${TYPE_WORDS})$|\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|(?:env:)?[A-Za-z_][A-Za-z0-9_]*)$|${POINTERS})`, 'i')

// Random by design and never a credential: a tool call's id, and a log or trace id under its own key.
const RANDOM_ID = /\b(?:srv)?toolu_[A-Za-z0-9]{20,}|\b(?:event_id|trace_id|span_id|tool_use_id|request_id)["']?\s*[:=]\s*["']?[A-Za-z0-9_+/=-]+/g

// The password in `postgres://user:PASSWORD@host`.
// The user name rule of 1.0.0, so every URL password 1.0.0 hid stays hidden, quotes in the user name included.
const URL_USER_NAME = String.raw`[^\s:/@]+`
const URL_PASSWORD = new RegExp(String.raw`(:\/\/${URL_USER_NAME}:)([^\s@/]{${MIN_URL_PASSWORD},})(@)`, 'gi')

const BEARER = /(\bBearer\s+)([A-Za-z0-9._~+/=-]{20,})/g

// A rule below may widen a span from the rules above, never narrow one.
// No rule below reads a value or URL longer than this, so each match costs one bounded read.
const MAX_VALUE_LENGTH = 4096
// After its closing quote a value ends at `,` `;` `)` `}` `]`, a `#` comment, or the end of the line.
const VALUE_END = String.raw`(?=\s*(?:[,;)}\]#]|$))`
const QUOTED_NAMED_VALUE = new RegExp(
  String.raw`(\b${SECRET_NAMES}["']?\s*[=:]\s*)(?:"""([^\n]{${MIN_NAMED_VALUE},${MAX_VALUE_LENGTH}}?)"""|'''([^\n]{${MIN_NAMED_VALUE},${MAX_VALUE_LENGTH}}?)'''|"((?:\\.|[^"\\\n]){${MIN_NAMED_VALUE},${MAX_VALUE_LENGTH}})"|'((?:\\'|[^'\n]){${MIN_NAMED_VALUE},${MAX_VALUE_LENGTH}})')${VALUE_END}`,
  'gimd',
)
// Inside escaped JSON each character arrives escaped once more: `\\\"` is a quote inside the value and `\"` closes it.
const ESCAPED_JSON_NAMED_VALUE = new RegExp(
  String.raw`(\b${SECRET_NAMES}\\"\s*:\s*\\")((?:\\\\\\"|\\\\\\\\|\\[^"\\]|[^\\"\n]){${MIN_NAMED_VALUE},${MAX_VALUE_LENGTH}})(?=\\")`,
  'gid',
)
// Text between two string literals is code, not a value: `"token: " + token + ", expires: "`, or ` . $token . ` in PHP.
const CONCATENATED = /^\s+(?:\+|\.\.?|\|\|)\s|\s(?:\+|\.\.?|\|\|)\s+$/
// In `"${DB_PASS:-default}"` only the default is a literal, so it alone is the value.
const SHELL_DEFAULT = /^(\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=?+])(.+)\}$/
const URL_USER = new RegExp(String.raw`:\/\/${URL_USER_NAME}:`, 'gi')
// The authority ends at "/", whitespace, a double quote or backtick, a single quote before `,` `}` `]` or `)`, or the next "://".
const AUTHORITY_END = /[/\s"`]|'[,}\])]|:\/\//y
const MAX_AUTHORITY_LENGTH = 1024
// A host (a name or a bracketed IPv6 address) and its port, then a character that ends the authority.
const HOST_AFTER_AT = /(?:[^\s@/?#"'`\\<>&|,;:)\]}[]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(?::\d{1,5})?(?=[/?#\s"'`\\<>&|,;)\]}]|$)/y

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

const isPlainWord = (value: string): boolean => /^[A-Za-z]+$/.test(value)

function groupSpans(text: string, pattern: RegExp, isNamed: (value: string) => boolean = () => false): Span[] {
  return [...text.matchAll(pattern)].map(m => {
    const start = m.index! + m[1]!.length
    return { start, end: start + m[2]!.length, named: isNamed(m[2]!) }
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
      last.parts ??= [{ ...last }]
      last.parts.push(s)
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
  const lineEnd = text.indexOf('\n', start)
  const m = REGEX_LITERAL.exec(text.slice(start, Math.min(lineEnd === -1 ? text.length : lineEnd, start + MAX_VALUE_LENGTH)))
  if (!m || !REGEX_SYNTAX.test(m[1]!)) return false
  try {
    new RegExp(m[1]!, m[2])
    return true
  } catch {
    return false
  }
}

// A value read from quotes, kept visible when it is a type, a pointer or code between two string literals.
function quotedValueSpans(text: string, pattern: RegExp): Span[] {
  return [...text.matchAll(pattern)].flatMap(m => {
    const group = m.findIndex((g, i) => i >= 2 && g !== undefined)
    const value = m[group]!
    if (NOT_A_QUOTED_SECRET.test(value) || CONCATENATED.test(value)) return []
    const [start, end] = m.indices![group]!
    const shell = SHELL_DEFAULT.exec(value)
    return [shell ? { start: start + shell[1]!.length, end: end - 1, named: true } : { start, end, named: true }]
  })
}

// A URL password runs to the last "@" that a host follows within the authority, so it may hold "@", "#", "?" or "'".
function urlAuthoritySpans(text: string): Span[] {
  const spans: Span[] = []
  for (const m of text.matchAll(URL_USER)) {
    const start = m.index! + m[0].length
    const limit = Math.min(text.length, start + MAX_AUTHORITY_LENGTH)
    let stop = start
    for (; stop < limit; stop++) {
      AUTHORITY_END.lastIndex = stop
      if (AUTHORITY_END.test(text)) break
    }
    let end = -1
    for (let at = start; at < stop; at++) {
      if (text[at] !== '@') continue
      HOST_AFTER_AT.lastIndex = at + 1
      if (at - start >= MIN_URL_PASSWORD && HOST_AFTER_AT.test(text)) end = at
    }
    if (end !== -1) spans.push({ start, end, named: isPlainWord(text.slice(start, end)) })
  }
  return spans
}

export function secretSpans(text: string): Span[] {
  return union([
    ...VENDOR_SHAPES.flatMap(p => wholeSpans(text, p)),
    ...groupSpans(text, NAMED_VALUE, () => true).filter(s => !NOT_A_SECRET_VALUE.test(text.slice(s.start, s.end)) && !isRegexLiteral(text, s.start)),
    // A letters-only URL password is a word like "postgres"; one with a digit or symbol is a real password, masked everywhere.
    ...groupSpans(text, URL_PASSWORD, isPlainWord),
    ...groupSpans(text, BEARER),
    ...withoutRandomIds(text, highEntropySpans(text)),
    ...quotedValueSpans(text, QUOTED_NAMED_VALUE),
    ...quotedValueSpans(text, ESCAPED_JSON_NAMED_VALUE),
    ...urlAuthoritySpans(text),
  ])
}
