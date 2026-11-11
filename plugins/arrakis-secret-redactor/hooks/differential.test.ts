import { expect, test } from 'claude-code/testing'

import { secretSpans } from './detect'
import { secretSpans as v1Spans } from '../test-fixtures/v1.0.0/detect'
import { Vault as V1Vault } from '../test-fixtures/v1.0.0/vault'
import { Vault } from './vault'

// Every value is built at run time, so the file holds no secret-shaped text.
const j = (...parts: string[]): string => parts.join('')

type Case = { label: string; text: string }

const URL_USERS = ['app', "o'connor", "d'angelo-smith", 'first.last', 'user+tag', 'a_b-c', 'd%40x', 'user~1', 'ADMIN', 'x!$&*', 'u,v', 'u;v', 'a=b', 'ünï', "user'", "'user", "o''connor", 'a"b', 'a`b']
const URL_PASSWORDS = [j('Xk9q', 'Lm2v'), j('p@', 'ss1'), j('pa#', 'ss9'), j('pa?', 's9'), j("pa'", 'ss9'), j('p%40', 'ss9'), j('hun', 'ter22'), j('pa,', 'ss9')]
const SCHEMES = ['postgres', 'mongodb+srv', 'redis', 'https', 'jdbc:postgresql']
const HOSTS = ['db.example.com', 'db.example.com:5432/app?sslmode=require', '[::1]:6379', 'my_db', '10.0.0.5:5432/app', 'h1:27017,h2:27017/db']
const URL_CONTEXTS: ((url: string) => string)[] = [
  url => url,
  url => `DATABASE_URL=${url}`,
  url => `"${url}"`,
  url => `{"url":"${url}","pool":5}`,
  url => `url: '${url}'`,
  url => `[db](${url})`,
  url => `<${url}>`,
  url => `connect ${url}, retry`,
  url => `{\\"url\\":\\"${url}\\"}`,
]

const NAMES = ['password', 'DB_PASSWORD', 'apiKey', 'client_secret', 'x-api-key', 'AUTH_TOKEN', 'privateKey', 'pwd']
const NAMED_VALUES = [j('Xk9q', 'Lm2v', 'Rt8w'), j('hun', 'ter', '22x'), j('p@ss', 'w0rd!'), j('null', '&Void', '#2024x'), j('$uper', 'man1!'), j('Summer', '2024!')]
const NAMED_SHAPES: ((name: string, value: string) => string)[] = [
  (n, v) => `${n}=${v}`,
  (n, v) => `export ${n}=${v}`,
  (n, v) => `${n}: ${v}`,
  (n, v) => `${n} = "${v}"`,
  (n, v) => `${n}='${v}'`,
  (n, v) => `"${n}": "${v}"`,
  (n, v) => `{"${n}":"${v}","next":1}`,
  (n, v) => `${n}: ${v} # rotated`,
  (n, v) => `${n}=${v};next=1`,
  (n, v) => `{\\"${n}\\":\\"${v}\\"}`,
  (n, v) => `--${n}=${v} --verbose`,
]

const TOKEN = j('Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa')
const TOKEN_SHAPES = [`Authorization: Bearer ${TOKEN}`, `"Bearer ${TOKEN}"`, `token ${TOKEN} end`, `'${TOKEN}'`, `(${TOKEN})`, `${j('gh', 'p_')}${TOKEN}`, `key=${TOKEN},x=1`]

function cases(): Case[] {
  const out: Case[] = []
  for (const user of URL_USERS)
    for (const password of URL_PASSWORDS)
      for (const scheme of SCHEMES)
        for (const host of HOSTS)
          URL_CONTEXTS.forEach((wrap, c) =>
            out.push({ label: `url user=${user} password#${URL_PASSWORDS.indexOf(password)} scheme=${scheme} host=${host} context#${c}`, text: wrap(`${scheme}://${user}:${password}@${host}`) }),
          )
  for (const name of NAMES)
    NAMED_VALUES.forEach((value, v) =>
      NAMED_SHAPES.forEach((shape, s) => out.push({ label: `named name=${name} value#${v} shape#${s}`, text: shape(name, value) })),
    )
  TOKEN_SHAPES.forEach((text, t) => out.push({ label: `token shape#${t}`, text }))
  return out
}

// Misses counted per user and password (or name and value), so one failure reads as one cause, not thousands of lines.
function byShape(missed: string[]): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const label of missed) {
    const shape = label.replace(/ (scheme|host|context|shape)[=#]\S+/g, '').replace(/ \[.*$/, '')
    counts[shape] = (counts[shape] ?? 0) + 1
  }
  return counts
}

const covered =(spans: { start: number; end: number }[], start: number, end: number): boolean => {
  for (let at = start; at < end; at++) if (!spans.some(s => s.start <= at && at < s.end)) return false
  return true
}

// The generated cases take seconds on a shared CI runner, past the 5-second default.
const SLOW = { timeoutMs: 30_000 }

test('hides every character 1.0.0 hid, across generated URLs, named values and tokens', SLOW, () => {
  const missed: string[] = []
  for (const { label, text } of cases()) {
    const now = secretSpans(text)
    for (const old of v1Spans(text)) if (!covered(now, old.start, old.end)) missed.push(`${label} [${old.start},${old.end})`)
  }
  expect(byShape(missed)).toEqual({})
})

test('hides again in later results every value 1.0.0 hid again, except a short piece of a wider password', SLOW, () => {
  const missed: string[] = []
  for (const { label, text } of cases()) {
    const now = new Vault('t')
    const before = new V1Vault('t')
    now.mask(text)
    before.mask(text)
    const spans = secretSpans(text)
    for (const old of v1Spans(text)) {
      const value = text.slice(old.start, old.end)
      const later = `echo ${value} z`
      if (before.mask(later).text.includes(value) || !now.mask(later).text.includes(value)) continue
      const wider = spans.find(s => s.start <= old.start && s.end >= old.end && s.end - s.start > value.length)
      if (wider !== undefined && (value.length < 6 || /^\d+$/.test(value))) continue
      missed.push(`${label} [${old.start},${old.end})`)
    }
  }
  expect(byShape(missed)).toEqual({})
})
