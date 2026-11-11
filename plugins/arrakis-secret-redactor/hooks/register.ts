import type { EngineInterface as Engine, Register } from 'claude-code'

import { Vault, maskDeep, placeholdersIn } from './vault'

const NAME = 'Arrakis Secret Redactor'
const HOMEPAGE = 'https://github.com/Arrakis-Security/claude-code-plugins'
const WITHHELD = `${NAME} could not check this result for secrets, so it was withheld.`
const WRITE_GUARD_FAILED = `${NAME} could not check this write for placeholders, so it was refused.`
let vault = new Vault()
let maskedThisSession = 0

// On macOS and Linux "\" and ":" are legal in a file name, so they count as Windows syntax only in a Windows-shaped path.
const isWindowsPath = (path: string): boolean => /^[A-Za-z]:|^\\\\/.test(path) || (path.includes('\\') && !path.includes('/'))

const lastSeparator = (path: string): number =>
  isWindowsPath(path) ? Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) : path.lastIndexOf('/')

// A drive-relative path (`C:x`), a network path, or a name with a ":" (an NTFS stream such as `.env.example:x`) cannot be placed.
const isUnplaceableOnWindows = (path: string, name: string): boolean =>
  /^[A-Za-z]:(?![\\/])/.test(path) || /^[\\/]{2}/.test(path) || name.includes(':')

// Where a write lands once every symbolic link is followed; a broken link or a name like ".." lands nowhere safe.
async function realTarget($: Engine, path: string): Promise<string | undefined> {
  const cut = lastSeparator(path)
  const name = path.slice(cut + 1)
  if (['', '.', '..'].includes(name) || (isWindowsPath(path) && isUnplaceableOnWindows(path, name))) return undefined
  const own = await $.fs.stat(path, { resolve: true }).catch(() => undefined)
  if (own) return own.realPath
  // The folder keeps its separator, so a drive root stays that root; Windows and git both accept "/" in the joined path.
  const folder = await $.fs.stat(cut < 0 ? '.' : path.slice(0, cut + 1), { resolve: true }).catch(() => undefined)
  if (folder?.realPath === undefined) return undefined
  return `${folder.realPath.replace(isWindowsPath(folder.realPath) ? /[\\/]$/ : /\/$/, '')}/${name}`
}

// A placeholder may become real again only where its real target is a file git ignores, or where the same file already held it.
async function isGitIgnored($: Engine, path: string): Promise<boolean> {
  const real = await realTarget($, path)
  if (real === undefined) return false
  const dir = real.slice(0, lastSeparator(real) + 1)
  const { exitCode } = await $.process.run(['git', 'check-ignore', '-q', real], { cwd: dir })
  return exitCode === 0
}

// Claude Code shows the plugin's name in front of its status line, so the text leaves the name out.
export function countLine(count: number): string {
  return `🛡️ ${count} secret${count === 1 ? '' : 's'} hidden from Claude this session`
}

export function introduced(newText: string, oldText: string): string[] {
  const before = placeholdersIn(oldText)
  return [...placeholdersIn(newText)].filter(p => !before.has(p))
}

function refuseWriteBack(path: string, placeholders: string[]): { deny: string } {
  return {
    deny: `${NAME}: ${placeholders.join(', ')} stand for real secrets, and ${path} is not a git-ignored file, the only kind a real value may go into. Write the secret only into a git-ignored file such as .env, or leave it out. How it works: ${HOMEPAGE}`,
  }
}

function refuseUnknown(placeholders: string[]): { deny: string } {
  return {
    deny: `${NAME}: ${placeholders.join(', ')} came from an earlier session, and the values they stood for are gone. Read the file again for current placeholders.`,
  }
}

export const register: Register = on => {
  // A reload starts the count at 0 but keeps the line an earlier load pinned.
  on('session.start', async ($, e, next) => {
    $.ui.status(undefined)
    return next(e)
  })

  // `/clear` starts a new session without a session.start or a reload, so the values and the count reset here.
  on('session.end', async ($, e, next) => {
    vault = new Vault()
    maskedThisSession = 0
    $.ui.status(undefined)
    return next(e)
  })

  on('tool.call', { tool: 'Write' }, async ($, e, next) => {
    const added = introduced(e.content, '')
    if (added.length === 0) return next(e)
    if (!(await isGitIgnored($, e.file_path))) return refuseWriteBack(e.file_path, added)
    const unknown = added.filter(p => !vault.knows(p))
    if (unknown.length > 0) return refuseUnknown(unknown)
    return next({ ...e, content: vault.unmask(e.content) })
  }).catch(($, e, next) => (next.called ? next(e) : { deny: WRITE_GUARD_FAILED }))

  on('tool.call', { tool: 'Edit' }, async ($, e, next) => {
    // A file that holds the placeholder text itself (a test fixture) is edited as written.
    const current = await $.fs.read(e.file_path).catch(() => '')
    if (placeholdersIn(e.old_string).size > 0 && current.includes(e.old_string)) return next(e)
    const added = introduced(e.new_string, e.old_string)
    if (added.length > 0 && !(await isGitIgnored($, e.file_path))) return refuseWriteBack(e.file_path, added)
    const unknown = added.filter(p => !vault.knows(p))
    if (unknown.length > 0) return refuseUnknown(unknown)
    return next({ ...e, old_string: vault.unmask(e.old_string), new_string: vault.unmask(e.new_string) })
  }).catch(($, e, next) => (next.called ? next(e) : { deny: WRITE_GUARD_FAILED }))

  // This keeps the value from Claude, not from the network: a git-ignored file that a Write filled in can still be run or sent.
  on('tool.call', async ($, e, next) => {
    const isFileWrite = e.tool === 'Write' || e.tool === 'Edit'
    if (!isFileWrite && placeholdersIn(JSON.stringify(e)).size > 0) {
      return {
        deny: `${NAME}: a ‹SECRET_…› placeholder stands for a secret Claude never sees, and only Write and Edit may carry one. Ask the user to run this step themselves. How it works: ${HOMEPAGE}`,
      }
    }

    const ran = await next(e)
    if (ran.deny !== undefined) return ran
    // A skill's instructions ride in the messages `ref` names; any rebuilt result would drop them.
    if (e.tool === 'Skill') return ran

    const tally = { count: 0 }
    // A failed call's result is bare text that no rebuilt result passes validation as; its masked text goes back as the refusal.
    if (ran.isError) return { deny: vault.mask(String(ran.text ?? ran.result ?? '')).text }

    const result = maskDeep(ran.result, vault, tally)
    const context = ran.context?.map(c => maskDeep(c, vault, tally) as string)
    // Nothing masked: return core's own answer, whose `ref` carries the messages core made, such as a skill's instructions.
    if (tally.count === 0) return ran
    maskedThisSession += tally.count
    $.ui.toast(`${NAME}: hid ${tally.count} secret(s) from ${e.tool}`)
    $.ui.status(countLine(maskedThisSession))
    // A fresh object without `ref`: core would otherwise reuse the unmasked messages it produced.
    return { result, context, isError: ran.isError } as typeof ran
  }).catch(($, e, next) => ({ deny: WITHHELD }))
}
