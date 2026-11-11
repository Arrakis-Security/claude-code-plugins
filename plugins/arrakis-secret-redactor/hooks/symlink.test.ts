import { type TestBody, expect, test } from 'claude-code/testing'

// Built at run time, so this file holds no placeholder of its own.
const OLD = ['‹SECRET', 'old1', '1›'].join('_')

type Stat = { kind: 'file' | 'dir'; size: number; mtimeMs: number; isLink: boolean; realPath?: string }
const file = (realPath: string, isLink = false): Stat => ({ kind: 'file', size: 1, mtimeMs: 0, isLink, realPath })
const dir = (realPath: string): Stat => ({ kind: 'dir', size: 0, mtimeMs: 0, isLink: false, realPath })

// Only `/repo/.env` and `/repo/.env.local` are git-ignored here.
function fakeRepo(on: Parameters<TestBody>[1],stats: Record<string, Stat>, checked: string[]) {
  on('fs.stat', (_$, e) => (stats[e.path] ? { value: stats[e.path] } : { deny: `no such file: ${e.path}` }) as never)
  on('process.run', (_$, e) => {
    const path = e.argv.at(-1)!
    checked.push(path)
    return { value: { exitCode: ['/repo/.env', '/repo/.env.local'].includes(path) ? 0 : 1, stdout: '', stderr: '' } } as never
  })
  on('fs.read', () => ({ value: 'KEY=old' }))
}

test('refuses a Write through an ignored symlink that points at a tracked file', async ($, on) => {
  const checked: string[] = []
  fakeRepo(on, { '/repo/.env': file('/repo/src/config.ts', true) }, checked)

  const ran = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `KEY=${OLD}` } as never)
  expect(ran.deny).toContain('is not a git-ignored file')
  expect(checked).toEqual(['/repo/src/config.ts'])
})

test('refuses an Edit through a symlinked folder that leads into tracked files', async ($, on) => {
  const checked: string[] = []
  fakeRepo(on, { '/repo/secrets/config.ts': file('/repo/src/config.ts'), '/repo/secrets': dir('/repo/src') }, checked)

  const ran = await $.tool.call({ tool: 'Edit', file_path: '/repo/secrets/config.ts', old_string: 'KEY=old', new_string: `KEY=${OLD}` } as never)
  expect(ran.deny).toContain('is not a git-ignored file')
  expect(checked).toEqual(['/repo/src/config.ts'])
})

test('checks a new file by its real folder', async ($, on) => {
  const checked: string[] = []
  fakeRepo(on, { '/link': dir('/repo') }, checked)

  const ran = await $.tool.call({ tool: 'Write', file_path: '/link/.env', content: `KEY=${OLD}` } as never)
  expect(checked).toEqual(['/repo/.env'])
  expect(ran.deny).toContain('came from an earlier session')
})

test('allows a symlink that leads to another git-ignored file', async ($, on) => {
  const checked: string[] = []
  fakeRepo(on, { '/repo/.env': file('/repo/.env.local', true) }, checked)

  const ran = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `KEY=${OLD}` } as never)
  expect(ran.deny).toContain('came from an earlier session')
})

test('refuses a Write through a symlink whose target does not exist yet', async ($, on) => {
  const checked: string[] = []
  fakeRepo(on, { '/repo/.env': { kind: 'file', size: 0, mtimeMs: 0, isLink: true }, '/repo': dir('/repo') }, checked)

  const ran = await $.tool.call({ tool: 'Write', file_path: '/repo/.env', content: `KEY=${OLD}` } as never)
  expect(ran.deny).toContain('is not a git-ignored file')
  expect(checked).toEqual([])
})

test('refuses a write whose path leads nowhere it can resolve', async ($, on) => {
  const checked: string[] = []
  fakeRepo(on, {}, checked)

  const ran = await $.tool.call({ tool: 'Write', file_path: '/gone/.env', content: `KEY=${OLD}` } as never)
  expect(ran.deny).toContain('is not a git-ignored file')
  expect(checked).toEqual([])
})

test('refuses a write to a path it cannot place', async ($, on) => {
  const checked: string[] = []
  // Every path stats as a folder, so only the spelling check can refuse.
  on('fs.stat', (_$, e) => ({ value: dir(e.path) }) as never)
  on('process.run', (_$, e) => {
    checked.push(e.argv.at(-1)!)
    return { value: { exitCode: 0, stdout: '', stderr: '' } } as never
  })

  for (const file_path of ['C:.env', '\\\\server\\share\\.env', 'C:\\repo\\x:y.env', 'C:\\repo\\.env.example:x','/repo/..', '/repo/']) {
    const ran = await $.tool.call({ tool: 'Write', file_path, content: `KEY=${OLD}` } as never)
    expect({ file_path, refused: ran.deny?.includes('is not a git-ignored file') }).toEqual({ file_path, refused: true })
  }
  expect(checked).toEqual([])
})

test('reads "\\" and ":" as part of a file name outside Windows paths', async ($, on) => {
  const checked: string[] = []
  on('fs.stat', (_$, e) => ({ value: file(e.path) }) as never)
  on('process.run', (_$, e) => {
    checked.push(`${e.init?.cwd} ${e.argv.at(-1)}`)
    return { value: { exitCode: 1, stdout: '', stderr: '' } } as never
  })

  for (const file_path of ['/repo/a\\b.env', '/repo/x:local.env']) await $.tool.call({ tool: 'Write', file_path, content: `KEY=${OLD}` } as never)
  expect(checked).toEqual(['/repo/ /repo/a\\b.env', '/repo/ /repo/x:local.env'])
})
