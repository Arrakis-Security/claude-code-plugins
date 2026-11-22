import { expect, test } from 'claude-code/testing'

import { secretSpans } from './detect'
import { Vault } from './vault'

// Built at run time, so no secret-shaped literal sits in the file.
const WORD_PASSWORD = ['hun', 'ter2', 'Pass9'].join('')
const RANDOM = ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')
// Built at run time, so the file holds no workspace link for the public-safe check to flag.
const ATLASSIAN = ['example', 'atlassian', 'net'].join('.')

test('leaves types, literals and pointers to a secret alone', () => {
  const safe = [
    'credentialsValid: boolean',
    'function isSecret(token: string): boolean {',
    'passwordSet = undefined',
    'apiKey = process.env.API_KEY',
    'token: ${GITHUB_TOKEN}',
    'secretArn = var.db_secret_arn',
  ]
  for (const text of safe) expect(secretSpans(text)).toEqual([])
})

test('still hides a named value that is a real secret', () => {
  expect(secretSpans(`credentialsValid: ${WORD_PASSWORD}`)).toHaveLength(1)
  expect(secretSpans(`apiKey = ${RANDOM}`)).toHaveLength(1)
})

test('leaves tool call ids and log or trace ids alone', () => {
  const safe = [
    '"tool_use_id": "toolu_01MEAyZ2zwzrVGcDTDmy8Gnr"',
    'toolu_01KStVyAK6AepVjm3Hsc5Xp1 finished',
    'event_id: AwAAAZnjK8qT1Jx2bQAAABhBWm5qSzhxVEFBQ1pRMXJIcWJZQUFBQUEAAAAkMDE5OWUz',
  ]
  for (const text of safe) expect(secretSpans(text)).toEqual([])
})

test('leaves claude.ai artifact links and Jira atlOrigin tags alone', () => {
  const id = RANDOM.slice(0, 22)
  const safe = [
    `https://claude.ai/artifact/${id}`,
    `https://claude.ai/code/artifact/${id} (Dev demo)`,
    'https://claude.ai/code/artifact/0b6e4f0a-3c1d-4e2b-9f7a-5d8c2e1b4a90',
    `https://${ATLASSIAN}/browse/PROJ-1?atlOrigin=eyJ${RANDOM}`,
  ]
  for (const text of safe) expect({ text, spans: secretSpans(text) }).toEqual({ text, spans: [] })
})

test('still hides a random token in a link from another host or joined to an id', () => {
  const id = RANDOM.slice(0, 22)
  const hidden = [
    `https://example.com/artifact/${RANDOM}`,
    `https://evil-claude.ai/artifact/${id}`,
    `https://evil.com/claude.ai/artifact/${id}`,
    `https://claude.ai/artifact/${id}_${RANDOM}`,
    `https://evil.com/x?atlOrigin=eyJ${RANDOM}`,
    `see &atlOrigin=eyJ${RANDOM} here`,
    `https://x.${ATLASSIAN}/wiki?atlOrigin=eyJabc/${RANDOM}`,
  ]
  for (const text of hidden) expect({ text, found: secretSpans(text).length > 0 }).toEqual({ text, found: true })
})

test('hides the start of a JSON value after a URL only in that line, not in every later result', () => {
  const lines = [
    '{"url":"https://example.com","contact":"me@example.com"}',
    "{'url':'https://example.com','contact':'me@example.com'}",
    '[{"url":"https://example.com"},{"contact":"me@example.com"}]',
  ]
  for (const line of lines) {
    const vault = new Vault()
    expect({ line, count: vault.mask(line).count }).toEqual({ line, count: 1 })
    for (const later of ['{"message":"Not Found","members":2}', "{'message':'Not Found'}"]) {
      expect({ line, later: vault.mask(later).text }).toEqual({ line, later })
    }
  }
})

test('still hides a random-looking value after a URL in later results', () => {
  const password = ['Hunter', '2two'].join('')
  const vault = new Vault()
  vault.mask(`{"url":"https://example.com","dsn":"admin:${password}@db"}`)
  expect(vault.mask(`{"dsn":"admin:${password}@db"}`).text).not.toContain(password)
})

test('keeps hiding a short URL password in later results when the user name holds a quote and a comma', () => {
  const password = ['hun', 'ter2'].join('')
  const urls = [
    `postgres://o',x:${password}@db.example.com/app`,
    `postgres://a"}b:${password}@db.example.com/app`,
    `'postgres://o",x:${password}@db.example.com/app'`,
  ]
  for (const url of urls) {
    const vault = new Vault()
    vault.mask(url)
    expect({ url, count: vault.mask(`echo ${password}`).count }).toEqual({ url, count: 1 })
  }
})

test('reads a JSON value after a URL as the next field wherever the URL sits in its string', () => {
  const value = ['"me', ':x'].join('')
  const lines = [
    `{"msg":"see https://example.com","contact":${value}@example.com"}`,
    `{"url":"jdbc:postgresql://db.example.com","contact":${value}@example.com"}`,
    `{"url":"(https://example.com)","contact":${value}@example.com"}`,
    `{"url":"https://example.com?q=it's","contact":${value}@example.com"}`,
    `{\\"url\\":\\"https://example.com\\",\\"contact\\":\\${value}@example.com\\"}`,
  ]
  for (const line of lines) {
    const vault = new Vault()
    expect({ line, count: vault.mask(line).count }).toEqual({ line, count: 1 })
    const later = `{"contact":${value}"}`
    expect({ line, later: vault.mask(later).text }).toEqual({ line, later })
  }
})

test('leaves a claude.ai or Jira link alone only when it starts its own URL', () => {
  const id = RANDOM.slice(0, 22)
  const safe = [
    `[demo](https://claude.ai/artifact/${id})`,
    `<https://claude.ai/artifact/${id}|demo>`,
    `"https://claude.ai/artifact/${id}"`,
    `"line\\nhttps://claude.ai/artifact/${id}"`,
    `<p>https://claude.ai/artifact/${id}</p>`,
    `url=https://claude.ai/artifact/${id}`,
    `name,https://claude.ai/artifact/${id}`,
    `**https://claude.ai/artifact/${id}**`,
    `"see\\thttps://${ATLASSIAN}/browse/PROJ-1?atlOrigin=eyJ${RANDOM}"`,
  ]
  for (const text of safe) expect({ text, spans: secretSpans(text) }).toEqual({ text, spans: [] })
  const hidden = [
    `https://evil.example/r?next=https://claude.ai/artifact/${id}`,
    `https://evil.example/r?next=(https://claude.ai/artifact/${id})`,
    `https://evil.example/r?next=[https://claude.ai/artifact/${id}]`,
    `https://evil.example/https://claude.ai/code/artifact/${id}`,
    `https://evil.example/r?next=https://${ATLASSIAN}/browse/PROJ-1?atlOrigin=eyJ${RANDOM}`,
  ]
  for (const text of hidden) expect({ text, found: secretSpans(text).length > 0 }).toEqual({ text, found: true })
})

test('parses the outer URL, so a link inside another URL is hidden also after an apostrophe', () => {
  const id = RANDOM.slice(0, 22)
  const first = ['‹SECRET', 't', '1›'].join('_')
  const direct = [
    `https://claude.ai/artifact/${id}`,
    `https://claude.ai/code/artifact/0b6e4f0a-3c1d-4e2b-9f7a-5d8c2e1b4a90`,
    `see it's here: https://claude.ai/artifact/${id}`,
    `'https://claude.ai/artifact/${id}'`,
    `https://${ATLASSIAN}/browse/PROJ-1?atlOrigin=eyJ${RANDOM}`,
  ]
  for (const text of direct) expect({ text, out: new Vault('t').mask(text).text }).toEqual({ text, out: text })
  const outers = [
    "https://evil.example/it's?next=",
    "https://evil.example/r?q=a'b&next=",
    "https://evil.example/o'neil/",
    'https://evil.example/r?n=x|',
    'https://evil.example\\',
    'https://evil.example/ü?next=',
    'https://evil.example/{x}?next=',
  ]
  for (const outer of outers) {
    const text = `${outer}https://claude.ai/artifact/${id}`
    expect({ text, out: new Vault('t').mask(text).text }).toEqual({ text, out: `${outer}https://claude.ai/artifact/${first}` })
  }
  const jira = `https://evil.example/it's?next=https://${ATLASSIAN}/browse/PROJ-1?atlOrigin=eyJ${RANDOM}`
  expect(new Vault('t').mask(jira).text).not.toContain(RANDOM)
})

test('keeps later results readable after prose with an apostrophe before the URL', () => {
  const lines = [
    `{"msg":"It's at https://example.com","contact":"me@example.com"}`,
    `{"msg":"It's at https://example.com","contact":"me:x@example.com"}`,
  ]
  for (const line of lines) {
    const vault = new Vault('t')
    expect({ line, count: vault.mask(line).count }).toEqual({ line, count: 1 })
    expect({ line, later: vault.mask('{"message":"Not Found"}').text }).toEqual({ line, later: '{"message":"Not Found"}' })
  }
})

test('keeps later results readable after an escaped quote before the URL', () => {
  const lines = [
    String.raw`{"msg":"The guide says \"See also\" at https://example.com","contact":"me@example.com"}`,
    String.raw`{\"msg\":\"The guide says \\\"See also\\\" at https://example.com\",\"contact\":\"me@example.com\"}`,
    String.raw`{'msg':'It\'s at https://example.com','contact':'me@example.com'}`,
    String.raw`[{"msg":"a \"b\" https://example.com"},{"contact":"me@example.com"}]`,
    `'{"url":"https://example.com","contact":"me@example.com"}',`,
  ]
  for (const line of lines) {
    const vault = new Vault('t')
    expect({ line, count: vault.mask(line).count }).toEqual({ line, count: 1 })
    expect({ line, later: vault.mask('{"message":"Not Found"}').text }).toEqual({ line, later: '{"message":"Not Found"}' })
  }
})

test('scans many escaped quotes before a URL quickly', () => {
  const password = ['ab', '12cd'].join('')
  let text = ''
  for (let k = 0; text.length < 200_000; k++) text += `${'\\'.repeat(k)}"x`
  const started = Date.now()
  secretSpans(text + ` s://a\\\\\\",:${password}@h`.repeat(2000))
  expect(Date.now() - started).toBeLessThan(500)
})

test('still hides a random token that is not under an id key', () => {
  expect(secretSpans(`value: ${RANDOM}`)).toHaveLength(1)
})

test('hides a plain-word value only where its name points at it', () => {
  const vault = new Vault()
  expect(vault.mask('password: correcthorse').count).toBe(1)
  expect(vault.mask('the correcthorse example').text).toBe('the correcthorse example')
})

test('keeps hiding a random-looking value everywhere once seen', () => {
  const vault = new Vault()
  vault.mask(`password: ${WORD_PASSWORD}`)
  expect(vault.mask(`echo ${WORD_PASSWORD}`).count).toBe(1)
})

test('hands a Skill result back as core made it, so its instructions arrive', async ($, on) => {
  on('ui.toast', () => ({ value: undefined }))
  on('tool.call', () => ({ result: { success: true, commandName: `release-notes ${RANDOM}` }, ref: 7 }) as never)

  const ran = await $.tool.call({ tool: 'Skill', skill: 'release-notes' } as never)
  expect((ran as { ref?: number }).ref).toBe(7)
})

test('hides a plain-word URL password only inside its URL', () => {
  const vault = new Vault()
  const word = ['data', 'base'].join('')
  expect(vault.mask(`postgres://app:${word}@db:5432/app`).text).not.toContain(word)
  expect(vault.mask(`the ${word} is up`).text).toBe(`the ${word} is up`)
})

test('scans one long run of a repeated keyword quickly', () => {
  const started = Date.now()
  secretSpans('token'.repeat(40_000))
  expect(Date.now() - started).toBeLessThan(500)
})

test('hides a URL password with a digit or symbol everywhere it appears later', () => {
  const vault = new Vault()
  expect(vault.mask(`postgres://app:${WORD_PASSWORD}@db:5432/app`).text).not.toContain(WORD_PASSWORD)
  expect(vault.mask(`login failed for ${WORD_PASSWORD}`).text).not.toContain(WORD_PASSWORD)
})

test('leaves a template, a ternary and a shell message under a secret name readable', () => {
  const safe = [
    'password: "${{ secrets.DB_PASSWORD }}"',
    'password: "{{ .Values.db.password }}"',
    `password: "<%= ENV['DB_PASSWORD'] %>"`,
    'PASSWORD="$(cat /run/secrets/pw)"',
    'secret_id = "${local.slug}/app/shared"',
    "showPassword ? 'Hide password' : 'Show password'",
    'TOKEN="${SLACK_INFRA_PROD_NOTIFICATIONS_TOKEN:-}"',
    'echo "${DB_PASSWORD:?DB_PASSWORD must be set}"',
    'PASSWORD="${DB_PASSWORD:?must be set}"',
  ]
  for (const text of safe) expect({ text, spans: secretSpans(text) }).toEqual({ text, spans: [] })
})

test('still hides a real value next to a template, a quoted key or a shell default', () => {
  const hidden = [
    `X="\${DB_PASSWORD:-${WORD_PASSWORD}}"`,
    `PASSWORD="\${A}\${DB_PASSWORD:-${WORD_PASSWORD}}"`,
    `{"db_password": "${WORD_PASSWORD}"}`,
    `{'my-password' : '${WORD_PASSWORD}'}`,
    `{"spring.datasource.password": "${WORD_PASSWORD}"}`,
    `{"Admin Password": "${WORD_PASSWORD}"}`,
    `ok ? x : {"password": "${WORD_PASSWORD}"}`,
    `Is this right? "password": "${WORD_PASSWORD}"`,
    `password: "{{x}};${WORD_PASSWORD}"`,
    `password: "$(echo '${WORD_PASSWORD}')"`,
    `password: '{{ .Values.x | default "${WORD_PASSWORD}" }}'`,
    `password: "{{x}} ${WORD_PASSWORD}"`,
    `DB_PASSWORD=+${WORD_PASSWORD}`,
    `DB_PASSWORD: ?${WORD_PASSWORD}`,
  ]
  for (const text of hidden) expect({ text, leaks: new Vault().mask(text).text.includes(WORD_PASSWORD) }).toEqual({ text, leaks: false })
})
