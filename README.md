<h1 align="center">Claude Code plugins from Arrakis</h1>

<p align="center">
  Open-source plugins that make Claude Code safer to run on real projects.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Claude_Code-marketplace-9d1d1d" alt="Claude Code marketplace">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-9d1d1d" alt="License: Apache-2.0"></a>
  <img src="https://img.shields.io/badge/by-Arrakis_Security-111111" alt="By Arrakis Security">
</p>

A [Claude Code plugin marketplace](https://code.claude.com/docs/en/plugins/create-marketplace.md) from [Arrakis Security](https://github.com/Arrakis-Security).

| Plugin | What it does |
|---|---|
| <img src="plugins/arrakis-secret-redactor/.claude-plugin/icon.png" width="20" alt=""> [Arrakis Secret Redactor](plugins/arrakis-secret-redactor/README.md) | Hides secrets in tool results from Claude, and writes real values back only into git-ignored files |

## Install

The plugins need Claude Code v2.1.287 or later. Run `claude --version` to check yours.

Add the marketplace once:

```
/plugin marketplace add Arrakis-Security/claude-code-plugins
```

Then install a plugin by name:

```
/plugin install arrakis-secret-redactor@arrakis-security
```

To get new versions without asking, run `/plugin`, open the **Marketplaces** tab, select **arrakis-security**, then select **Enable auto-update**.

Each plugin's README covers its own setup, including installs for a whole organization.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security problem, see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). Anyone who shares this code, changed or not, keeps the [NOTICE](NOTICE) file with it. The license gives no rights to the Arrakis name or logo.
