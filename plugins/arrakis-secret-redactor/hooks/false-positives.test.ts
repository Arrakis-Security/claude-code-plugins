import { expect, test } from 'claude-code/testing'

import { secretSpans } from './detect'
import { Vault } from './vault'

// Built at run time, so no secret-shaped literal sits in the file.
const WORD_PASSWORD = ['hun', 'ter2', 'Pass9'].join('')
const RANDOM = ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')

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
