import { expect, test } from 'claude-code/testing'

const RANDOM = ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')

test('pins the hidden-secret count under the prompt, and clears it when the session ends', async ($, on) => {
  const statuses: (string | undefined)[] = []
  on('ui.toast', () => ({ value: undefined }))
  on('session.end', () => ({ sessionId: 's1' }))
  on('ui.status', (_$, e) => {
    statuses.push(e.text)
    return { value: undefined }
  })
  on('tool.call', () => ({ result: { stdout: `DB_PASSWORD=${RANDOM}`, stderr: '', interrupted: false } }))

  const ran = await $.tool.call({ tool: 'Bash', command: 'cat config.txt' } as never)
  expect(JSON.stringify(ran)).not.toContain(RANDOM)
  expect(statuses.at(-1)).toBe('🛡️ 1 secret hidden from Claude this session')

  await $.session.end({ reason: 'clear' } as never)
  expect(statuses.at(-1)).toBeUndefined()
})
