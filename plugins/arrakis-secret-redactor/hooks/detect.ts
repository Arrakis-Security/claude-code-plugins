// Detection rules adapted from secrets-veil (MIT, github.com/yonatangross/orchestkit, mods/secrets-veil).

// `named`: only a rule that reads the text around it caught it (a name, a URL's user part for a plain word, or a user part that crosses JSON fields), so that text is the evidence, not the value.
// `parts`: the spans a wider one absorbed, so each value a rule found alone is still hidden again later.
export type Span = { start: number; end: number; named?: boolean; parts?: Span[]; kind?: string }

const ENTROPY_MIN_LENGTH = 20
// Hex (git shas, hashes) tops out at 4.0 bits per character and a UUID at 4.09, so neither can cross 4.3.
const ENTROPY_THRESHOLD = 4.3
export const RANDOM_TOKEN = 'random-looking token'
export const PRIVATE_KEY = 'private key'
const URL_PASSWORD_KIND = 'URL password'
// "=" counts only as base64 padding at the end, so `KEY=value` scores the value alone.
const TOKEN_RUN = /[A-Za-z0-9+/_-]{20,}={0,2}/g

const VENDOR_SHAPES: readonly (readonly [string, RegExp])[] = [
  ['Anthropic key', /sk-ant-[A-Za-z0-9_-]{20,}/g],
  ['OpenAI key', /\bsk-[A-Za-z0-9_-]{20,}/g],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{20,}/g],
  ['GitHub token', /\bgithub_pat_[A-Za-z0-9_]{20,}/g],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ['Stripe key', /\b[sr]k_live_[A-Za-z0-9]{16,}/g],
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g],
  ['1Password token', /\bops_[A-Za-z0-9_-]{20,}/g],
  [PRIVATE_KEY, /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g],
]

const SECRET_NAMES = String.raw`[A-Za-z0-9_]{0,64}(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)[A-Za-z0-9_]{0,64}`
const MIN_NAMED_VALUE = 6
const MIN_URL_PASSWORD = 3

// The secret is group 2: `DB_PASSWORD=hunter22`, `"clientSecret": "abc"`, `api_key: abc`.
const NAMED_VALUE = new RegExp(String.raw`(\b${SECRET_NAMES}["']?\s*[=:]\s*["']?)((?:(?<!\s)|(?!#))[^\s"'\`,;]{${MIN_NAMED_VALUE},})`, 'gi')

// A type, a literal or a pointer to where the value lives is not the value: `credentialsValid: boolean`, `key = process.env.KEY`.
const TYPE_WORDS = 'boolean|string|number|bigint|object|unknown|any|void|never|null|undefined|true|false'
const POINTERS = String.raw`process\.env\.|os\.environ|var\.|local\.`
const NOT_A_SECRET_VALUE = new RegExp(String.raw`^(?:(?:${TYPE_WORDS})\b|\$\{?[A-Za-z_]|#\{|${POINTERS})`, 'i')
// Inside quotes only the whole value is a type, literal or variable: `"string"` and `"${TOKEN}"` are, `"$uperman1!"` and`"null&Void#2024x"` are passwords.
const NOT_A_QUOTED_SECRET = new RegExp(String.raw`^(?:(?:${TYPE_WORDS})$|\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|(?:env:)?[A-Za-z_][A-Za-z0-9_]*)$|${POINTERS})`, 'i')

// Random by design and not a credential: a tool call's id, a log or trace id under its own key, a claude.ai artifact id, and the `atlOrigin` tag Atlassian adds to its links.
// The two link ids match only in a link with no earlier "//" in the same run of URL characters, so not one inside another URL's path or query, on their own host and in their own shape, with nothing joined after them.
const RANDOM_ID =
  /\b(?:srv)?toolu_[A-Za-z0-9]{20,}|\b(?:event_id|trace_id|span_id|tool_use_id|request_id)["']?\s*[:=]\s*["']?[A-Za-z0-9_+/=-]+|(?<=(?<!\/\/[^\s"'`<>]*?)https:\/\/claude\.ai\/(?:code\/)?artifact\/)(?:[A-Za-z0-9]{22}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?![A-Za-z0-9_+/=-])|(?<=(?<!\/\/[^\s"'`<>]*?)https:\/\/[a-z0-9-]+\.atlassian\.net\/[^\s?#"'<>]*\?(?:[^\s#"'<>&]*&)*atlOrigin=)eyJ[A-Za-z0-9_-]{8,512}(?![A-Za-z0-9_+/=-])/g

// The password in `postgres://user:PASSWORD@host`.
// The user name rule of 1.0.0, so every URL password 1.0.0 hid stays hidden, quotes in the user name included.
const URL_USER_NAME = String.raw`[^\s:/@]+`
const URL_PASSWORD = new RegExp(String.raw`(:\/\/${URL_USER_NAME}:)([^\s@/]{${MIN_URL_PASSWORD},})(@)`, 'gi')
const CROSSES_FIELDS = /["'`]\s*[,}\]]/
const ENDS_FIELD: Record<string, RegExp> = { '"': /"\s*[,}\]]/, "'": /'\s*[,}\]]/, '`': /`\s*[,}\]]/ }

// A user part ran across fields of a JSON line or a dict only when it closes the string value the URL sits in.
// A user name may hold `'` and `,`, so outside such a value the password keeps its usual replay.
function crossesFields(text: string, at: number, lead: string): boolean {
  if (!CROSSES_FIELDS.test(lead)) return false
  let open = at - 1
  while (open >= 0 && !`"'\`\n`.includes(text[open]!)) open--
  if (open < 0 || text[open] === '\n' || !ENDS_FIELD[text[open]!]!.test(lead)) return false
  // A quote opens a value after `:` `[` `,` `{` or the line start, also as `\"` in escaped JSON.
  let before = open - 1
  if (text[before] === '\\') before--
  while (before >= 0 && (text[before] === ' ' || text[before] === '\t')) before--
  return before < 0 || ':[,{\n'.includes(text[before]!)
}

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
      if (shannonEntropy(run) >= ENTROPY_THRESHOLD) spans.push({ start: m.index!, end: m.index! + run.length, kind: RANDOM_TOKEN })
      continue
    }
    let at = 0
    for (const part of parts) {
      const start = m.index! + run.indexOf(part, at)
      at = start - m.index! + part.length
      if (!isWordLike(part) && part.length >= ENTROPY_MIN_LENGTH && shannonEntropy(part) >= ENTROPY_THRESHOLD) {
        spans.push({ start, end: start + part.length, kind: RANDOM_TOKEN })
      }
    }
  }
  return spans
}

const isPlainWord = (value: string): boolean => /^[A-Za-z]+$/.test(value)

const nameIn = (lead: string): string => {
  const name = /[\w-]+/.exec(lead)![0]
  return secretSpans(name).length === 0 ? name : 'secret'
}

function groupSpans(
  text: string,
  pattern: RegExp,
  kindOf: (lead: string) => string,
  isNamed: (value: string, lead: string, at: number) => boolean = () => false,
): Span[] {
  return [...text.matchAll(pattern)].map(m => {
    const start = m.index! + m[1]!.length
    return { start, end: start + m[2]!.length, named: isNamed(m[2]!, m[1]!, m.index!), kind: kindOf(m[1]!) }
  })
}

// dotenv reads `abc12345#prod` as `abc12345` and a comment, so the part before the "#" is hidden again later too.
function withPartBeforeHash(text: string, span: Span): Span[] {
  const hash = text.indexOf('#', span.start)
  return hash > span.start && hash < span.end ? [span, { ...span, end: hash }] : [span]
}

function wholeSpans(text: string, pattern: RegExp, kind?: string): Span[] {
  return [...text.matchAll(pattern)].map(m => ({ start: m.index!, end: m.index! + m[0].length, kind }))
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
  // A key line seen again on its own keeps the private-key label, so the notice never shows its characters.
  for (const span of merged) {
    if (span.kind !== PRIVATE_KEY && !span.parts?.some(p => p.kind === PRIVATE_KEY)) continue
    span.kind = PRIVATE_KEY
    for (const part of span.parts ?? []) part.kind = PRIVATE_KEY
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
    const kind = nameIn(m[1]!)
    return [shell ? { start: start + shell[1]!.length, end: end - 1, named: true, kind } : { start, end, named: true, kind }]
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
    if (end !== -1) spans.push({ start, end, named: isPlainWord(text.slice(start, end)) || crossesFields(text, m.index!, m[0]), kind: URL_PASSWORD_KIND })
  }
  return spans
}

export function secretSpans(text: string): Span[] {
  return union([
    ...VENDOR_SHAPES.flatMap(([kind, p]) => wholeSpans(text, p, kind)),
    ...groupSpans(text, NAMED_VALUE, nameIn, () => true).filter(s => !NOT_A_SECRET_VALUE.test(text.slice(s.start, s.end)) && !isRegexLiteral(text, s.start)).flatMap(s => withPartBeforeHash(text, s)),
    // A letters-only URL password is a word like "postgres", and one after fields of a JSON line is the start of the next value: both stay hidden only where the rule finds them.
    ...groupSpans(text, URL_PASSWORD, () => URL_PASSWORD_KIND, (value, lead, at) => isPlainWord(value) || crossesFields(text, at, lead)),
    ...groupSpans(text, BEARER, () => 'Bearer token'),
    ...withoutRandomIds(text, highEntropySpans(text)),
    ...quotedValueSpans(text, QUOTED_NAMED_VALUE),
    ...quotedValueSpans(text, ESCAPED_JSON_NAMED_VALUE),
    ...urlAuthoritySpans(text),
  ])
}
