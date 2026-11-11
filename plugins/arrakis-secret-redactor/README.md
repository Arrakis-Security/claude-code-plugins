<p align="center">
  <img src=".claude-plugin/icon.png" width="112" alt="Arrakis Secret Redactor shield">
</p>

<h1 align="center">Arrakis Secret Redactor</h1>

<p align="center">
  <b>Let Claude work with your config files while the secrets in them stay hidden.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-plugin-9d1d1d" alt="Claude Code plugin">
  <img src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2FArrakis-Security%2Fclaude-code-plugins%2Fmain%2Fplugins%2Farrakis-secret-redactor%2F.claude-plugin%2Fplugin.json&query=%24.version&label=version&color=9d1d1d" alt="Version">
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-9d1d1d" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/by-Arrakis_Security-111111" alt="By Arrakis Security">
</p>

When a tool result holds an API key, a token or a password, the plugin swaps the value for a placeholder before Claude sees it. Claude still edits the file, and the real value goes back only into files that git ignores.

<p align="center">
  <img src="images/status-line.png" alt="The Claude Code prompt, with the status line: arrakis-secret-redactor, 2 secrets hidden from Claude this session">
</p>

## Why it matters

Every tool result becomes part of the conversation that Claude Code sends to the model, again on every turn. A key that shows up once in `cat .env` stays in that conversation. Once the plugin hides a value, only its placeholder travels.

## What Claude sees

Your project has a git-ignored `.env`:

```
DB_PASSWORD=<your real password>
```

Claude runs `cat .env` and reads this:

```
DB_PASSWORD=‹SECRET_k3j9x2ab_1›
```

The line under the chat input counts what the plugin hid:

<p align="center">
  <img src="images/status-line-after-task.png" alt="The status line after a task: arrakis-secret-redactor, 1 secret hidden from Claude this session">
</p>

## How it works

- **Every tool result except a skill's is checked.** That covers Bash, Read, Grep, web fetches and MCP tools (tools from MCP, the Model Context Protocol, servers). Each secret becomes a placeholder such as `‹SECRET_k3j9x2ab_2›`. The same secret gets the same placeholder for the whole session.
- **Real values go back only into git-ignored files.** Before a write, the plugin follows symbolic links and asks git whether the real file is ignored. In an ignored file such as `.env`, it swaps each placeholder back for its real value. In any other file, it refuses the write.
- **Other tools can't carry a placeholder.** If Claude puts a placeholder in a Bash command or another tool's input, the plugin refuses the call and asks Claude to hand that step to you.
- **Values stay in memory.** The plugin keeps the real values in memory for the current session only. It never writes them to disk, to a log or to Claude Code's storage. A placeholder from an earlier session can't be turned back into a value.
- **Fails closed.** If the plugin can't check a result, it withholds the result. If it can't check a write, it refuses the write.

## What it detects

- Token formats from known vendors: Anthropic, OpenAI, GitHub, Slack, Stripe, AWS access key IDs, 1Password service account tokens, and PEM (Privacy-Enhanced Mail format) private keys
- A value under a name that points at a secret, such as `DB_PASSWORD=`, `"clientSecret":` or `api_key:`. An unquoted value runs to the next space, quote, `,`, `;` or `#`. A quoted value is hidden whole, spaces and escaped quotes included, in plain or escaped JSON, when its closing quote ends the line or comes before `,`, `;`, `)`, `}`, `]` or a `#` comment.
- The password in a URL such as `postgres://user:password@host`, up to the last `@` before the host, so a password may hold `@`, `#`, `?` or `'`
- A `Bearer` token
- A long random-looking string (one with high Shannon entropy, a measure of how random the characters are)

Git commit hashes, UUIDs (universally unique IDs), file paths, package integrity hashes, tool call IDs and trace IDs are left alone.

## Limits

- **Detection is pattern-based.** A secret in a format the rules don't know can get through, and a random-looking value that isn't a secret can be hidden.
- **It covers tool results only.** A secret you type or paste into the prompt reaches Claude.
- **A skill's text is not checked.** A skill can run a shell command while it loads, and that command's output reaches Claude as the skill returned it.
- **Images and PDFs reach Claude unchanged.** The plugin checks text only, so a secret shown in a screenshot, written in a PDF or stored in the file's metadata reaches Claude.
- **A quoted value counts whole only when a value's end follows its closing quote.** Otherwise the general rule applies, which hides it only up to its first space.
- **Text under a secret-sounding name is hidden even when it is prose.** `"passwordHint": "Use at least 8 characters"` is hidden whole, and so is the same sentence in later results. A URL whose query holds an `@` has its host hidden too, and in a JSON line such as `{"url":"https://example.com","contact":"me@example.com"}`, the start of the email after the URL is hidden.
- **A value shaped like a variable is left visible.** `"$DB_PASSWORD"`, `"${TOKEN}"` and an unquoted `$TOKEN` name where a secret lives, so a real password such as `"$uperman1"` or an unquoted `$uper2024!` is left visible too.
- **A URL password is hidden again wherever it shows up later, even when it is short.** After `redis://u:2024@host`, a later `Copyright 2024` shows as a placeholder.
- **The write check follows symbolic links, not hard links.** A git-ignored file that is a hard link to a tracked file counts as ignored.
- **It hides values from Claude. Your programs can still read them.** A git-ignored file that Claude filled in can still be run or sent over the network.
- **OpenTelemetry (a standard for tracing app activity) traces see tool output first.** When Claude Code exports OpenTelemetry traces, the `claude_code.tool` span can hold a tool's output as the tool returned it, before this plugin hides anything.

## Where it runs

| Surface | Runs | Tested |
|---|---|---|
| Claude Code CLI, including `claude -p` | Yes | macOS, in a terminal and in cmux (a terminal app for macOS) |
| Claude Code in VS Code | Yes | macOS |
| The Code tab in the Claude desktop app | Yes | macOS |
| The Claude desktop app under WSL (Windows Subsystem for Linux) | No | |
| Chat on claude.ai, and Cowork | No | |

Linux and Windows are not tested yet.

It needs Claude Code v2.1.287 or later.

## Install it for yourself

In Claude Code:

```
/plugin marketplace add Arrakis-Security/claude-code-plugins
/plugin install arrakis-secret-redactor@arrakis-security
```

Then run `/reload-plugins`, or start a new session.

From a shell:

```
claude plugin marketplace add Arrakis-Security/claude-code-plugins
claude plugin install arrakis-secret-redactor@arrakis-security
```

## Turn on updates

Claude Code doesn't update plugins from this marketplace until you turn auto-update on. Run `/plugin`, open the **Marketplaces** tab, select **arrakis-security**, then select **Enable auto-update**. Claude Code then checks for a new version after each session starts, and the next session loads it.

An admin can turn it on for every user in managed settings:

```json
{
  "extraKnownMarketplaces": {
    "arrakis-security": {
      "source": { "source": "github", "repo": "Arrakis-Security/claude-code-plugins" },
      "autoUpdate": true
    }
  }
}
```

## Install it for your organization

A plugin installed from GitHub counts as the user's own. If your managed settings (the admin-controlled settings file for Claude Code) set `allowManagedModsOnly`, Claude Code refuses it. To run the plugin as your organization's, follow [Install your organization's mods](https://code.claude.com/docs/en/plugins/mods/admin.md#install-your-organizations-mods):

1. With your device management tool, copy a release of this repository to the same path on every machine, for example `/opt/arrakis/claude-code-plugins`. Make that directory, and every directory above it, writable only by an administrator.
2. Add these keys to managed settings:

```json
{
  "extraKnownMarketplaces": {
    "arrakis-security": {
      "source": { "source": "directory", "path": "/opt/arrakis/claude-code-plugins" }
    }
  },
  "enabledPlugins": { "arrakis-secret-redactor@arrakis-security": true },
  "prependPlugins": ["arrakis-secret-redactor@arrakis-security", "sec-default@builtin"]
}
```

`prependPlugins` runs the redactor ahead of every mod a user installs, so it sees each tool result after those mods have run. Keep `sec-default@builtin` in that list: it is Claude Code's built-in guard.

The managed settings file lives at:

| OS | Path |
|---|---|
| macOS | `/Library/Application Support/ClaudeCode/managed-settings.json` |
| Linux | `/etc/claude-code/managed-settings.json` |
| Windows | `C:\Program Files\ClaudeCode\managed-settings.json` |

## Check that it works

1. In a git repository, add `.env` to `.gitignore`, and create `.env` with a line such as `API_KEY=` followed by any 32 random letters and digits.
2. Ask Claude: `Run cat .env and tell me what you see.`
3. Claude reports a placeholder in place of the value, and the line under the chat input shows `1 secret hidden from Claude this session`.

## Turn it off

Run `/plugin`, pick **arrakis-secret-redactor** and turn it off. From a shell:

```
claude plugin disable arrakis-secret-redactor@arrakis-security
```

## Credits

Built by Hatzav Aviv at [Arrakis Security](https://github.com/Arrakis-Security). The detection rules are adapted from secrets-veil, part of [OrchestKit](https://github.com/yonatangross/orchestkit) (MIT License). See [THIRD_PARTY_NOTICES](../../THIRD_PARTY_NOTICES).

## License

[Apache-2.0](../../LICENSE). See [NOTICE](../../NOTICE).
