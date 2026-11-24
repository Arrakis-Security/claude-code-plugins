import { expect, test } from 'claude-code/testing'

import { Vault } from './vault'

// Built at run time, so no secret-shaped literal sits in the file.
const SECRETS = [['hun', 'ter2', 'Pass9'].join(''), ['HUN', 'TER2', '_PASS9'].join('')]
const DOLLAR = '$'
const KEYS = ['password', 'DB_PASSWORD', 'api_token']
// Each form puts a literal `<S>` in a slot of a template the redactor may keep readable.
const FORMS = [
  `${DOLLAR}{{ <S> }}`,
  `${DOLLAR}{{ secrets.X || '<S>' }}`,
  `${DOLLAR}{{ format('{0}', '<S>') }}`,
  `${DOLLAR}{{ secrets.X }}<S>`,
  `{{ <S> }}`,
  `{{ .Values.x | default "<S>" }}`,
  `{{ default "<S>" .Values.x }}`,
  `{{ .Values.x }}<S>`,
  `<S>{{ .Values.x }}`,
  `<%= <S> %>`,
  `<%= ENV['X'] || '<S>' %>`,
  `<%= ENV.fetch('X', '<S>') %>`,
  `#{<S>}`,
  `#{ENV['X'] || '<S>'}`,
  `#{ENV.fetch('X', '<S>')}`,
  `${DOLLAR}{env:X, <S>}`,
  `${DOLLAR}{env:X} <S>`,
  `${DOLLAR}{X:-<S>}`,
  `${DOLLAR}{X:=<S>}`,
  `${DOLLAR}{X:+<S>}`,
  `${DOLLAR}{X}<S>`,
  `<S>${DOLLAR}{X}`,
  `${DOLLAR}(echo <S>)`,
  `${DOLLAR}(printf '%s' <S>)`,
  `${DOLLAR}(cat /run/x) <S>`,
  `${DOLLAR}(echo -<S>)`,
  `${DOLLAR}(echo --<S>)`,
]

const quote = (value: string): string => (value.includes('"') ? `'${value}'` : `"${value}"`)

test('hides a literal secret in every slot of a template under a secret name', () => {
  const leaks: string[] = []
  for (const secret of SECRETS)
    for (const form of FORMS)
      for (const key of KEYS)
        for (const separator of ['=', ': ']) {
          const text = `${key}${separator}${quote(form.replace('<S>', secret))}`
          if (new Vault().mask(text).text.includes(secret)) leaks.push(text.replace(secret, '<S>'))
        }
  expect(leaks).toEqual([])
})
