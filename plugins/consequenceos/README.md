# ConsequenceOS for Claude Code

A policy on every file edit, shell command and MCP call Claude Code makes. Each call is allowed, asked about or blocked before it runs. Secrets stay out of reach, the agent can't switch the guard off, and a tamper-evident log records what it did. It runs on your machine, with no server and no database. Nothing leaves your machine.

## Install

In Claude Code:

```
/plugin install consequenceos --marketplace Matutozi/Consequence-OS
```

On Claude Code older than 2.1.275, add the marketplace first:

```
/plugin marketplace add Matutozi/Consequence-OS
/plugin install consequenceos@consequenceos
```

Then restart Claude Code. Linux and macOS only.

## What happens the first time

1. The plugin downloads `consequenced`, the program that decides each call, from this repository's [releases](https://github.com/Matutozi/Consequence-OS/releases): about 9 MB, once. The download has to match a checksum that ships inside the plugin, or it isn't installed. On a slow connection it may take more than one try: each try carries on where the last stopped.
2. It writes a starter policy to `~/.consequence/claude-code.yaml`, unless you have one. It never overwrites your rules.

Until both are done, every tool call is blocked, with a message saying why. ConsequenceOS fails closed: if it can't decide a call, the call doesn't run.

## What the starter policy does

| Claude Code wants to | What happens |
|---|---|
| Read or search files | Goes ahead |
| Edit or create a file in the project | Goes ahead (Claude Code may still ask, by its own settings) |
| Edit a file outside the project | Asks you |
| Run `git status`, `git diff`, `git log`, `ls`, `pwd` | Goes ahead, if it's only that command |
| Run any other command, or anything with `;`, `&&`, `\|`, `$(…)` or a redirect | Asks you |
| Read or write `.env` files, SSH keys, cloud credentials | Blocked, and Claude is told why |
| Change Claude Code's settings, its plugins, or ConsequenceOS's own policy and log | Blocked |
| Use an MCP tool you haven't listed | Asks you |

ConsequenceOS only ever makes Claude Code stricter: a call it allows still goes through Claude Code's own permissions.

## Changing the rules

Edit `~/.consequence/claude-code.yaml`. Rules are checked top to bottom and the first match wins. [ConsequenceOS on your own machine](../../docs/personal.md#changing-the-rules) has examples, and [Guarding Claude Code](../../docs/claude-code.md) is the full reference.

To check a change, see the log or run the policy's tests, install `consequenced` on your `PATH` too ([releases](https://github.com/Matutozi/Consequence-OS/releases), or `go install github.com/matutozi/consequence-os/cmd/consequenced@latest`):

```bash
consequenced -hook claude-code -check                       # the rules, and warnings about risky ones
consequenced -test ~/.consequence/claude-code.test.yaml     # the policy's tests
consequenced -hook claude-code -log                         # the last 20 decisions
consequenced -hook claude-code -verify-audit                # check nobody edited the log
```

## Settings

These environment variables, set where you start Claude Code, change what the plugin runs:

| Variable | Effect |
|---|---|
| `CONSEQUENCEOS_BIN` | Run this `consequenced` instead of downloading one, such as one you built from source |
| `CONSEQUENCEOS_POLICY` | Use this policy instead of `~/.consequence/claude-code.yaml` |

## Good to know

- **Set up with `consequenced -init claude-code` before?** Remove that hook entry from `.claude/settings.local.json` or `~/.claude/settings.json`, or every call is checked twice. Your policy stays where it is, and the plugin uses it.
- **It isn't a sandbox.** Claude Code runs the hook, not the operating system. It stops the calls Claude Code makes through its tools. See [what it doesn't cover](../../docs/claude-code.md#what-this-doesnt-cover).
- **Uninstalling** with `/plugin uninstall consequenceos` removes the hook. Your policy and log stay in `~/.consequence`.
