# claude-code-plugins

Everything in this repository is public, including commit messages, branch names, and pull request titles and bodies.

- Keep internal and private details out of files, commits, branch names and pull requests: ticket keys, links to internal tools, internal hostnames, code names, customer names, personal details and real secrets. `CONTRIBUTING.md` lists them under "Keep internal details out".
- Follow the rest of `CONTRIBUTING.md` too.
- Sign and sign off every commit: `git commit -S -s`.
- Before every push, run `.github/scripts/check-public-safe.sh origin/main HEAD` and fix what it finds.
