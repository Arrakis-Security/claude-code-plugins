import { expect, test } from 'claude-code/testing'

import { secretSpans } from './detect'

test('leaves a regex literal under a secret-sounding name alone', () => {
  const safe = [
    'const TOKEN_RUN = /[A-Za-z0-9+/_-]{20,}={0,2}/g',
    'const URL_PASSWORD = /(\\b[a-z][a-z0-9+.-]*:\\/\\/[^\\s:/@]+:)([^\\s@/]{3,})(@)/gi',
    'const NOT_A_SECRET_VALUE = /^(?:(?:boolean|string)\\b|\\$\\{?[A-Za-z_]|process\\.env\\.)/i',
    '  tokenPattern: /^gh[pousr]_\\w+$/,',
    'const apiKeyShape = /\\bsk-[A-Za-z0-9_-]{20,}/g;',
  ]
  for (const text of safe) expect(secretSpans(text)).toEqual([])
})

test('still hides a value that only looks like a regex literal', () => {
  const word = ['hun', 'ter2', 'Pass9'].join('')
  const hidden = [
    `password: /${word}/`,
    `DB_PASSWORD=/${word}`,
    `api_key = /${word}/g extra`,
    `secret = /(${word}/g`,
  ]
  for (const text of hidden) expect(secretSpans(text)).toHaveLength(1)
})
