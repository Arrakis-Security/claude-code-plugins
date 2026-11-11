import { expect, test } from 'claude-code/testing'

import { secretSpans } from './detect'
import { introduced } from './register'
import { Refusal, Vault, maskDeep } from './vault'

// Synthetic values built at run time, so no secret-shaped literal sits in the file.
const RANDOM = 'q8Zr2Lx9Vb4Nw7Kt1Hy6Jm3Pd5Sf0Ga'
const GITHUB = ['gh', 'p_'].join('') + 'aB3dE6fG9hJ2kL5mN8pQ1rS4tU7vW0xY3z'

function masked(text: string): string {
  return new Vault('t').mask(text).text
}

test('hides vendor tokens, named values, URL passwords and random tokens', () => {
  expect(masked(`token ${GITHUB} end`)).toBe('token ‹SECRET_t_1› end')
  expect(masked('DB_PASSWORD=hunter22x')).toBe('DB_PASSWORD=‹SECRET_t_1›')
  expect(masked('"clientSecret": "abcdef12"')).toBe('"clientSecret": "‹SECRET_t_1›"')
  expect(masked('postgres://app:s3cretpw@db.example.com:5432/app')).toBe('postgres://app:‹SECRET_t_1›@db.example.com:5432/app')
  expect(masked(`key=${RANDOM}`)).toBe('key=‹SECRET_t_1›')
  expect(masked(`token-${RANDOM}-staging`)).toBe('token-‹SECRET_t_1›-staging')
})

test('leaves git shas, UUIDs, paths and prose alone', () => {
  const safe = [
    'commit 2643eb7ac6cf35f1c42dbc5d9426652a8775a978',
    'id 8811f6b4-1eb4-40d3-87bd-2df1fb13606e',
    '/Users/me/.claude/worktrees/fix+TKT-782-invalidate-stale-caches/apps/backend',
    'The password field is required before the user can sign in.',
    'integrity sha512-Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4cXV1eA==',
    '/private/tmp/bundled-skills/2.1.296/c6956f76e06bbf204124c4b81b922ea0/plugin-authoring',
  ]
  for (const text of safe) expect(secretSpans(text)).toEqual([])
})

test('gives the same secret the same number and puts it back on unmask', () => {
  const vault = new Vault('t')
  const first = vault.mask(`A=${RANDOM}\nB=${GITHUB}\nC=${RANDOM}`).text
  expect(first).toBe('A=‹SECRET_t_1›\nB=‹SECRET_t_2›\nC=‹SECRET_t_1›')
  expect(vault.unmask(first)).toBe(`A=${RANDOM}\nB=${GITHUB}\nC=${RANDOM}`)
  expect(vault.unmask('‹SECRET_t_9› unknown')).toBe('‹SECRET_t_9› unknown')
})

test('never reads a placeholder from an earlier process as one of its own', () => {
  const earlier = new Vault()
  const later = new Vault()
  const old = earlier.mask(`key=${RANDOM}`).text.slice('key='.length)
  later.mask(`key=${GITHUB}`)
  expect(earlier.knows(old)).toBe(true)
  expect(later.knows(old)).toBe(false)
  expect(later.unmask(old)).toBe(old)
})

test('keeps hiding a value it has seen even where no rule matches it', () => {
  const vault = new Vault('t')
  vault.mask('DB_PASSWORD=hunter22x')
  expect(vault.mask('echo hunter22x').text).toBe('echo ‹SECRET_t_1›')
})

test('masks nested results and refuses shapes it cannot rebuild', () => {
  const vault = new Vault('t')
  const tally = { count: 0 }
  expect(maskDeep({ stdout: `DB_PASSWORD=hunter22x`, code: 0, lines: ['ok'] }, vault, tally)).toEqual({
    stdout: 'DB_PASSWORD=‹SECRET_t_1›',
    code: 0,
    lines: ['ok'],
  })
  expect(tally.count).toBe(1)
  expect(() => maskDeep(new Map([['a', 'b']]), vault, tally)).toThrow(Refusal)
})

test('masks a secret that sits in an object key', () => {
  const tally = { count: 0 }
  const result = maskDeep({ [`key=${RANDOM}`]: true }, new Vault('t'), tally)
  expect(JSON.stringify(result)).not.toContain(RANDOM)
  expect(tally.count).toBe(1)
})

test('an edit may keep a placeholder the file held, never add a new one', () => {
  expect(introduced('X=‹SECRET_t_1›\nY=2', 'X=‹SECRET_t_1›')).toEqual([])
  expect(introduced('X=‹SECRET_t_1›\nY=‹SECRET_t_2›', 'X=‹SECRET_t_1›')).toEqual(['‹SECRET_t_2›'])
})
