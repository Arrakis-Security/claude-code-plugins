import { expect, test } from 'claude-code/testing'

import { secretSpans } from './detect'
import { secretSpans as v1Spans } from '../test-fixtures/v1.0.0/detect'
import { Vault as V1Vault } from '../test-fixtures/v1.0.0/vault'
import { Vault } from './vault'

// Every value below is built at run time, so the file holds no secret-shaped text and no placeholder.
const PASSWORD = ['hun', 'ter', '22x', 'Q9'].join('')
const SECOND = ['Zy98', 'xw76', 'Lm'].join('')
const PHRASE = ['correct', 'horse', 'battery', 'staple'].join(' ')
const SYMBOLS = ['pa55', 'word#9', '9,x'].join(';')
const RANDOM = ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')
const GITHUB = ['gh', 'p_'].join('') + RANDOM
const HUMAN = ['Summer', '2024!', 'Welc'].join('')
const SPACED = ['Xk9q', 'Lm2v', 'Rt8w'].join(' ')

// Text Claude reads, and the secret in it that must not survive masking.
const MUST_HIDE: [string, string][] = [
  [`DB_PASSWORD=${PASSWORD}`, PASSWORD],
  [`export TOKEN=${PASSWORD};`, PASSWORD],
  [`TOKEN=${PASSWORD};echo hi`, PASSWORD],
  [`password: ${PASSWORD}  # rotated monthly`, PASSWORD],
  [`password: "${PHRASE}" # rotated`, PHRASE],
  [`export DB_PASSWORD="my long phrase 9"  # prod`, 'my long phrase 9'],
  [`"password": "null&Void#2024x"`, 'null&Void#2024x'],
  [`"password": "true.north.77"`, 'true.north.77'],
  [`api_key = "${RANDOM}"`, RANDOM],
  [`"clientSecret": "${PHRASE}"`, PHRASE],
  [`password: '${PHRASE}'`, PHRASE],
  [`"password": "never gonna give you up 7"`, 'never gonna give you up 7'],
  [`"password": "true north 77"`, 'true north 77'],
  [`PASSWORD = """${PHRASE}"""`, PHRASE],
  [`"secret": "ab\\"${SYMBOLS}"`, `ab\\"${SYMBOLS}`],
  [`{\\"password\\":\\"${PHRASE}\\"}`, PHRASE],
  [`{\\"password\\":\\"ab\\\\\\"${SYMBOLS}\\"}`, `ab\\\\\\"${SYMBOLS}`],
  [`DB_PASSWORD="${HUMAN}`, HUMAN],
  [`password = 'it\\'s ${PHRASE}'`, PHRASE],
  [`PASSWORD='${PHRASE}\\'`, PHRASE],
  [`password:\n  "${PHRASE}"`, PHRASE],
  [`password: "${SPACED}"`, SPACED],
  ['POSTGRES_PASSWORD: "${DB_PASS:-' + PASSWORD + '}"', PASSWORD],
  [`"password": "$uper${PASSWORD}!"`, `$uper${PASSWORD}!`],
  [`${'x'.repeat(40)}://u:${PASSWORD}@h`, PASSWORD],
  [`password="${PASSWORD}\\"`, `${PASSWORD}\\`],
  [`DB_PASSWORD='${PASSWORD}\\'`, `${PASSWORD}\\`],
  [`Server=db;Password=${PASSWORD};Database=app;`, PASSWORD],
  [`token=${PASSWORD},user=bob`, PASSWORD],
  [`token:${PASSWORD},next:val`, PASSWORD],
  [`Authorization: Bearer ${RANDOM}`, RANDOM],
  [`remote: ${GITHUB}`, GITHUB],
  [`redis://default:${PASSWORD}@[::1]:6379`, PASSWORD],
  [`postgres://u:p@ss1@my_db:5432/app`, 'p@ss1'],
  [`postgres://u:pass@${PASSWORD}@my_db:5432/app`, `pass@${PASSWORD}`],
  [`{\\"url\\":\\"postgres://u:pass@${PASSWORD}@host\\"}`, `pass@${PASSWORD}`],
  [`<postgres://u:pass@${PASSWORD}@host>`, `pass@${PASSWORD}`],
  [`redis://u:pass@${PASSWORD}@host&x=1`, `pass@${PASSWORD}`],
  [`https://u:${PASSWORD}@api.example.com?notify=ops@example.com`, PASSWORD],
  [`postgres://u:${PASSWORD}@h1,postgres://u:${SECOND}@h2`, PASSWORD],
  [`postgres://u:${PASSWORD}@h1,postgres://u:${SECOND}@h2`, SECOND],
  [`postgres://o'connor:${PASSWORD}@db.example.com/app`, PASSWORD],
  [`url: 'postgres://d'angelo:${PASSWORD}@db.example.com/app'`, PASSWORD],
  [`postgres://user':${PASSWORD}@db.example.com/app`, PASSWORD],
  [`postgres://'user:${PASSWORD}@db.example.com/app`, PASSWORD],
  [`postgres://o''connor:${PASSWORD}@db.example.com/app`, PASSWORD],
  [`postgres://a"b:${PASSWORD}@db.example.com/app`, PASSWORD],
  [`postgres://a\`b:${PASSWORD}@db.example.com/app`, PASSWORD],
  ...['@', '#', '?', "'", '"', '`', ',', ')', '@b#', '@b,', '@b)', '@b?'].map(symbol => {
    const password = ['abc', 'd123'].join(symbol)
    return [`postgres://app:${password}@db.example.com:5432/app`, password] as [string, string]
  }),
]

// Text that holds no secret, and the part of it that must stay readable.
const MUST_KEEP: [string, string][] = [
  ['throw new Error("Invalid token: " + tokenValue)', '+ tokenValue)'],
  ['throw new Error("Invalid token: " + tokenValue + " for user " + id)', ' + tokenValue + '],
  ['log("password: " + pw + " end")', ' + pw + '],
  ['console.log("token: " + token + ", expires: " + exp)', ' + token + '],
  ['const s = "password=" + user.pass + "; host=" + host', ' + user.pass + '],
  ['print("api_key: " + key + ")")', ' + key + '],
  ['$s = "token: " . $token . ", user: " . $user;', ' . $token . '],
  ['const url = "?token=" + token + "&user=" + user', ' + token + '],
  ['credentialsValid: boolean', 'boolean'],
  ['apiKey = process.env.API_KEY', 'process.env.API_KEY'],
  ['passwordType: "string"', '"string"'],
  ['token: "${GITHUB_TOKEN}"', '${GITHUB_TOKEN}'],
  ['password: "$DB_PASSWORD"', '$DB_PASSWORD'],
  ['token: "$env:API_TOKEN"', '$env:API_TOKEN'],
  ['POSTGRES_PASSWORD: "${DB_PASSWORD:-changeme}"', '"${DB_PASSWORD:-'],
  [`Server=db;Password=${PASSWORD};Database=app;Encrypt=true`, 'Database=app;Encrypt=true'],
  [`token=${PASSWORD},user=bob`, 'user=bob'],
  [`token:${PASSWORD},next:val`, 'next:val'],
  [`{"url":"https://u:${PASSWORD}@host.io","owner":"me@corp.com"}`, '@host.io","owner":"me@corp.com"}'],
  [`{'url':'https://u:${PASSWORD}@host.io','owner':'me@corp.com'}`, "@host.io','owner':'me@corp.com'}"],
  ['{\\"token\\":\\"${GITHUB_TOKEN}\\",\\"passwordType\\":\\"string\\"}', '${GITHUB_TOKEN}'],
  ['{\\"token\\":\\"${GITHUB_TOKEN}\\",\\"passwordType\\":\\"string\\"}', 'string'],
  [`postgres://app:${PASSWORD}@db.example.com:5432/app`, '@db.example.com:5432/app'],
  ['http://localhost:5173/@vite/client', 'localhost:5173/@vite/client'],
  ['https://registry.npmjs.org:443/@types/node', 'registry.npmjs.org:443/@types/node'],
  ['http://localhost:3000/api/users/@me', 'localhost:3000/api/users/@me'],
  ['const TOKEN_RUN = /[A-Za-z0-9+/_-]{20,}={0,2}/g', '/[A-Za-z0-9+/_-]{20,}={0,2}/g'],
]

test('hides every listed secret', () => {
  for (const [text, secret] of MUST_HIDE) {
    expect({ text, leaked: new Vault().mask(text).text.includes(secret) }).toEqual({ text, leaked: false })
  }
})

test('keeps every listed text readable, also in later results', () => {
  for (const [text, visible] of MUST_KEEP) {
    const vault = new Vault()
    expect({ text, kept: vault.mask(text).text.includes(visible) }).toEqual({ text, kept: true })
    expect({ text, keptLater: vault.mask(`later: ${visible}`).text.includes(visible) }).toEqual({ text, keptLater: true })
  }
})

test('hides a random-looking secret again where it shows up alone later', () => {
  for (const [text, secret] of MUST_HIDE) {
    if (secret.length < 8 || !/[0-9]/.test(secret) || !/[A-Za-z]/.test(secret)) continue
    const vault = new Vault()
    vault.mask(text)
    expect({ text, leakedLater: vault.mask(`echo ${secret}`).text.includes(secret) }).toEqual({ text, leakedLater: false })
  }
})

// The fixture holds the 1.0.0 detect.ts and vault.ts unchanged, so this compares against the code that shipped.
test('never hides less than 1.0.0, now or later, except a short piece of a wider password', () => {
  const inputs = [...MUST_HIDE.map(([text]) => text), ...MUST_KEEP.map(([text]) => text)]
  // Text a MUST_KEEP case lists as readable is a 1.0.0 false positive, such as `"me` read as a URL password in JSON.
  const isKeptText = (text: string, start: number, end: number): boolean =>
    MUST_KEEP.some(([kept, visible]) => kept === text && start >= text.indexOf(visible) && end <= text.indexOf(visible) + visible.length)
  const urls = [['2024', 'Pass'].join('@'), ['9472', '016385'].join(''), ['ab', '12'].join(''), ['ab1', 'x'].join('@')].map(p => `postgres://u:${p}@host`)
  for (const text of [...inputs, ...urls]) {
    const now = new Vault('t')
    const before = new V1Vault('t')
    const masked = now.mask(text).text
    before.mask(text)
    const spans = secretSpans(text)
    for (const old of v1Spans(text)) {
      if (isKeptText(text, old.start, old.end)) continue
      const value = text.slice(old.start, old.end)
      expect({ text, value, hidden: !masked.includes(value) }).toEqual({ text, value, hidden: true })
      const later = `echo ${value} z`
      if (before.mask(later).text.includes(value) || !now.mask(later).text.includes(value)) continue
      const wider = spans.find(s => s.start <= old.start && s.end >= old.end && s.end - s.start > value.length)
      const isShortPiece = wider !== undefined && (value.length < 6 || /^\d+$/.test(value))
      expect({ text, value, isShortPiece }).toEqual({ text, value, isShortPiece: true })
      const replayed = text.slice(wider!.start, wider!.end)
      expect({ text, replayed, hiddenLater: !now.mask(`echo ${replayed}`).text.includes(replayed) }).toEqual({ text, replayed, hiddenLater: true })
    }
  }
})

test('hides a password with spaces again in later results', () => {
  const password = ['Summer', '2024!'].join(' ')
  const vault = new Vault()
  vault.mask(`password: "${password}"`)
  expect(vault.mask(`echo ${password}`).text.includes(password)).toBe(false)
})

test('reads long shaped inputs quickly', () => {
  const inputs = [
    'password:'.repeat(110_000),
    'password:"' + 'x'.repeat(100) + 'password:x'.repeat(100_000),
    'a://b:'.repeat(170_000),
    'x://u:p@h,'.repeat(20_000),
    'x://u:abc,'.repeat(20_000),
    'password: "'.repeat(20_000),
    'password=abcdefg '.repeat(20_000),
    `postgres://u:${'a'.repeat(5000)}`,
    'a.'.repeat(50_000),
    "x://o'c'o'n".repeat(50_000),
    'password="""'.repeat(100_000),
  ]
  for (const input of inputs) {
    const started = Date.now()
    new Vault().mask(input)
    expect({ input: input.slice(0, 20), slow: Date.now() - started > 5000 }).toEqual({ input: input.slice(0, 20), slow: false })
  }
})

test('never hides a short piece of a wider password again in later results', () => {
  const vault = new Vault()
  vault.mask('postgres://app:2024@Pass@db.example.com/app')
  expect(vault.mask('Copyright 2024 Acme').text).toBe('Copyright 2024 Acme')
})

test('reads a whole line of secrets as separate values', () => {
  expect(secretSpans(`postgres://u:${PASSWORD}@h1,postgres://u:${SECOND}@h2`)).toHaveLength(2)
})
