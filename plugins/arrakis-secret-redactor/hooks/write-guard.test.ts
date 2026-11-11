import { expect, test } from 'claude-code/testing'

// A resumed session still holds placeholders whose values died with the earlier process.
test('refuses a Write that carries a placeholder this process never made', async ($, on) => {
  let written = false
  on('process.run', () => ({ value: { exitCode: 0, stdout: '', stderr: '' } }) as never)
  on('fs.stat', (_$, e) => ({ value: { kind: 'file', size: 1, mtimeMs: 0, isLink: false, realPath: e.path } }) as never)
  on('tool.call', () => {
    written = true
    return { result: {} }
  })

  for (const content of ['KEY=‹SECRET_old1_1›', 'KEY=‹SECRET_1›']) {
    const ran = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content } as never)
    expect(ran.deny).toContain('came from an earlier session')
  }
  expect(written).toBe(false)
})

test('refuses a placeholder from before /clear, which ends the session without a reload', async ($, on) => {
  const random = ['Zx9qL', 'm2Vt8', 'RkW4p', 'Yb7Nc', 'J3sHd', 'Q6uFa'].join('')
  const written: string[] = []
  on('ui.toast', () => ({ value: undefined }))
  on('ui.status', () => ({ value: undefined }))
  on('session.end', () => ({ sessionId: 's1' }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: '', stderr: '' } }) as never)
  on('fs.stat', (_$, e) => ({ value: { kind: 'file', size: 1, mtimeMs: 0, isLink: false, realPath: e.path } }) as never)
  on('tool.call', (_$, e) => {
    if (e.tool === 'Write') written.push((e as { content: string }).content)
    return { result: { stdout: `DB_PASSWORD=${random}`, stderr: '', interrupted: false } }
  })

  const read = await $.tool.call({ tool: 'Bash', command: 'cat .env' } as never)
  const placeholder = JSON.stringify(read).match(/‹SECRET_[a-z0-9]+_\d+›/)![0]
  await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `KEY=${placeholder}` } as never)
  expect(written).toEqual([`KEY=${random}`])

  await $.session.end({ reason: 'clear' } as never)
  const ran = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `KEY=${placeholder}` } as never)
  expect(ran.deny).toContain('came from an earlier session')
  expect(written).toEqual([`KEY=${random}`])
})

test('refuses an Edit that adds a placeholder this process never made', async ($, on) => {
  let written = false
  on('fs.read', () => ({ value: 'KEY=old' }))
  on('process.run', () => ({ value: { exitCode: 0, stdout: '', stderr: '' } }) as never)
  on('fs.stat', (_$, e) => ({ value: { kind: 'file', size: 1, mtimeMs: 0, isLink: false, realPath: e.path } }) as never)
  on('tool.call', () => {
    written = true
    return { result: {} }
  })

  const ran = await $.tool.call({ tool: 'Edit', file_path: '/repo/.env', old_string: 'KEY=old', new_string: 'KEY=‹SECRET_old1_1›' } as never)
  expect(ran.deny).toContain('‹SECRET_old1_1› came from an earlier session')
  expect(written).toBe(false)
})
