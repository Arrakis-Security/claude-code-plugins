# Contributing

Pull requests are welcome. For a large change, open an issue first to agree on the approach.

## Sign off every commit

This repository uses the [Developer Certificate of Origin](https://developercertificate.org) (DCO). By signing off a commit, you certify that you wrote the change or have the right to submit it under this repository's license. Add the sign-off with `-s`:

```
git commit -s -m "Detect GitLab personal access tokens"
```

Git adds a line such as `Signed-off-by: Your Name <you@example.com>`. CI checks that every commit in a pull request has one.

Sign your commits with a GPG (GNU Privacy Guard) or SSH key too, because `main` only accepts signed commits. GitHub explains [how to set it up](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification).

## Keep internal details out

Treat everything here as public: the files, commit messages, branch names, and pull request titles and bodies. Keep these out of all of them:

- ticket keys and links from a company's internal tracker, chat, wiki or documents, such as Jira, Slack, Notion, Linear or Google Docs
- internal hostnames, project code names and customer names
- personal details, such as email addresses and phone numbers, apart from the sign-off line on your own commits
- screenshots that show any of the above
- real secrets, even ones that no longer work

Write commit subjects as `type: summary`, where the type is `feat`, `fix` or `improve`, for example `fix: Hide passwords in JDBC URLs`. Name branches the same way, as `type/short-name`. When a change needs a reference, link an issue in this repository.

CI fails a pull request when its commit messages, branch name, title, body or added lines match a pattern in `.github/public-safe-patterns.txt`. Maintainers keep more patterns in the `PUBLIC_SAFE_EXTRA_PATTERNS` Actions secret, one per line, so that the list itself stays private. A pull request from a fork gets no secrets, so CI checks it against the public list only. A branch is public as soon as you push it, so run the check before you push:

```
.github/scripts/check-public-safe.sh origin/main HEAD
```

To use the private list on your machine, put the same lines in `.github/public-safe-patterns.local.txt` in your main checkout. Git ignores this file, and the check reads it from every worktree of the checkout. The check fails if the file is committed. In CI, a failed check names only where the text is, because the logs of a public repo are public. Run the check on your machine to see the text.

CI also checks each comment and review on a pull request or issue against the same patterns. GitHub runs this check only after the comment is posted, so edit or delete a comment that fails it. An edited comment keeps its old versions visible, so delete a version that holds internal text from the comment's edit history too.

## Work on a plugin

You need Claude Code v2.1.287 or later.

1. Load your copy of the plugin in a session: `claude --plugin-dir plugins/arrakis-secret-redactor`. Claude Code reloads it when you change a file.
2. Run the tests: `claude plugin test plugins/arrakis-secret-redactor`
3. Check the plugin the way Claude Code loads it: `claude plugin validate plugins/arrakis-secret-redactor`
4. Check the marketplace: `claude plugin validate .`

Add a test for every change in behavior. Test values that look like secrets are built at run time, for example `['gh', 'p_'].join('')`, so the files hold no secret-shaped text. Never put a real secret in a test.

When your change should reach users, raise `version` in the plugin's `.claude-plugin/plugin.json`.

## Pull requests

- CI must pass, and a code owner must approve.
- Keep each pull request to one change.
- Releases are tagged `<plugin>-v<version>`, for example `arrakis-secret-redactor-v1.0.0`.
