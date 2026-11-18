import { expect, test } from 'claude-code/testing'

import { Vault } from './vault'

// Built at run time, so no secret-shaped literal or placeholder sits in the file.
const HASHED = ['abc', 'Def9', '#4R=-xYz#'].join('')
const GITHUB = ['gh', 'p_'].join('') + ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')
const FIRST = ['‹SECRET', 't', '1›'].join('_')

test('hides an unquoted value whole when it holds a "#"', () => {
  const out = new Vault('t').mask(`DB_PASSWORD=${HASHED}\nDB_PORT=5432`).text
  expect(out).toBe(`DB_PASSWORD=${FIRST}\nDB_PORT=5432`)
})

test('still ends a value at a "#" comment after whitespace', () => {
  expect(new Vault('t').mask(`DB_PASSWORD=${HASHED} # stage`).text).toBe(`DB_PASSWORD=${FIRST} # stage`)
})

test('names each hidden secret, showing only the last four characters of a long one', async ($, on) => {
  const toasts: string[] = []
  on('env.get', () => ({ value: undefined }))
  on('ui.toast', (_$, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  on('tool.call', () => ({ result: { stdout: `DB_PASSWORD=${HASHED}\nGH=${GITHUB}`, stderr: '', interrupted: false } }))

  await $.tool.call({ tool: 'Bash', command: 'cat .env' } as never)

  expect(toasts).toEqual([`Arrakis Secret Redactor: hid 2 secret(s) from Bash: DB_PASSWORD, GitHub token …${GITHUB.slice(-4)}`])
  expect(toasts[0]).not.toContain(HASHED)
})

const LONG = ['Qw8zLp3XvN', '7rT2mK9bYc', '4hJdF6sA1u', 'E5gR0iO3nV'].join('')
const SHORT = ['k3Vn', 'Q8wz', 'R2mx'].join('')

test('leaves a "#" comment right after the "=" or ":" visible, in this result and later ones', () => {
  const vault = new Vault('t')
  for (const text of ['API_KEY= #required', '$primary_token: #1a2b3c4d;', '.btn { color: #1a2b3c4d; }']) {
    expect(vault.mask(text)).toEqual({ text, count: 0, hidden: new Set() })
  }
})

test('reads a value that starts with "#" as a comment, with no space after the "=" or ":"', () => {
  const colour = ['#1a2', 'b3c4d'].join('')
  const vault = new Vault('t')
  for (const text of ['API_KEY=#required', 'api_token:#required', 'password=#{ENV}', `.a{--brand-token:${colour}}`, `$focus-token:${colour};`]) {
    expect(vault.mask(text)).toEqual({ text, count: 0, hidden: new Set() })
  }
})

test('hides the part before a "#" again in later results, as dotenv reads it', () => {
  const password = ['abc', '12345'].join('')
  const vault = new Vault('t')
  vault.mask(`DB_PASSWORD=${password}#prod`)
  expect(vault.mask(`connected with ${password} ok`).count).toBe(1)
})

test('names a secret "secret" when its name holds a value hidden earlier', () => {
  const short = ['Xk29', 'abQ7'].join('')
  const vault = new Vault('t')
  vault.mask(`DB_PASSWORD=${short}`)
  expect(vault.mask(`${short}_TOKEN=whatever1`).hidden).toEqual(new Set(['secret', 'DB_PASSWORD']))
})

test('labels each kind of secret, and the private key wins where matches overlap', () => {
  const pem = ['-----BEGIN ', 'PRIVATE KEY-----\\n', LONG, '\\n', LONG, '\\n-----END ', 'PRIVATE KEY-----\\n'].join('')
  const bearer = ['Bearer ', LONG].join('')
  const cases: [string, string[]][] = [
    [`{"type": "service_account", "private_key": "${pem}"}`, ['private key']],
    [`GITHUB_TOKEN=${GITHUB}`, [`GitHub token …${GITHUB.slice(-4)}`]],
    [`postgres://app:${LONG}@db.example.com/app`, [`URL password …${LONG.slice(-4)}`]],
    [`Authorization: ${bearer}`, [`Bearer token …${LONG.slice(-4)}`]],
    [`{\\"client_secret\\": \\"${SHORT}\\"}`, ['client_secret']],
  ]
  for (const [text, labels] of cases) expect({ text, hidden: new Vault('t').mask(text).hidden }).toEqual({ text, hidden: new Set(labels) })
})

test('shows no characters of a private key line seen again on its own', () => {
  const pem = ['-----BEGIN ', 'PRIVATE KEY-----\n', LONG, '\n', SHORT, LONG.slice(0, 10), '\n-----END ', 'PRIVATE KEY-----'].join('')
  const vault = new Vault('t')
  vault.mask(pem)
  expect(vault.mask(`found ${LONG}`).hidden).toEqual(new Set(['private key']))
})

test('never names a secret by a name that is itself a secret, and keeps the hyphens in a name', () => {
  const token = ['gh', 'p_'].join('') + ['Zx9qL', 'm2Token', 'RkW4p', 'Yb7Nc', 'J3sHd'].join('')
  const remote = new Vault('t').mask(`origin\thttps://${token}:x-oauth-basic@github.com/acme/app.git (fetch)`)
  expect(remote.text).not.toContain(token)
  expect([...remote.hidden].join()).not.toContain(token.slice(4, 12))
  expect(new Vault('t').mask(`X-Api-Key: ${SHORT}`).hidden).toEqual(new Set(['Api-Key']))
})

test('names a value by its name once a later result shows it under one', () => {
  const vault = new Vault('t')
  expect(vault.mask(LONG).hidden).toEqual(new Set([`random-looking token …${LONG.slice(-4)}`]))
  expect(vault.mask(`DB_PASSWORD=${LONG}`).hidden).toEqual(new Set([`DB_PASSWORD …${LONG.slice(-4)}`]))
})

test('names a value hidden again by replay as it was first named', () => {
  const vault = new Vault('t')
  vault.mask(`REDIS_PASSWORD=${SHORT}`)
  expect(vault.mask(`echo ${SHORT}`).hidden).toEqual(new Set(['REDIS_PASSWORD']))
})

test('shows no characters of a private key', () => {
  const pem = ['-----BEGIN ', 'PRIVATE KEY-----\n', LONG, LONG, '\n-----END ', 'PRIVATE KEY-----'].join('')
  expect(new Vault('t').mask(pem).hidden).toEqual(new Set(['private key']))
})

test('names three hidden secrets and counts the rest', async ($, on) => {
  const toasts: string[] = []
  on('env.get', () => ({ value: undefined }))
  on('ui.toast', (_$, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  const stdout = ['DB_PASSWORD', 'APP_SECRET', 'API_TOKEN', 'SMTP_PASSWD'].map((name, i) => `${name}=${SHORT}${i}`).join('\n')
  on('tool.call', () => ({ result: { stdout, stderr: '', interrupted: false } }))

  await $.tool.call({ tool: 'Bash', command: 'cat .env' } as never)

  expect(toasts).toEqual(['Arrakis Secret Redactor: hid 4 secret(s) from Bash: DB_PASSWORD, APP_SECRET, API_TOKEN +1 more'])
})
