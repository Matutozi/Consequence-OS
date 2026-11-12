# ConsequenceOS on your own machine

You don't need a team, a server or a database to use ConsequenceOS. If you use Claude Code on your own repositories, it can check every file edit and shell command before it runs, keep secrets out of reach, and keep a tamper-evident log of what your agent did. Nothing leaves your machine.

## Five minutes

**1. Install** `consequenced` on your `PATH`, from a [release](https://github.com/Matutozi/Consequence-OS/releases) or with `go install github.com/matutozi/consequence-os/cmd/consequenced@latest`. Linux and macOS only.

**2. Set it up** in the project you want to guard:

```bash
cd ~/code/my-project
consequenced -init claude-code
```

This does three things:
1. **Writes a starter policy** to `~/.consequence/claude-code.yaml`, unless you already have one. It never overwrites your rules.
2. **Shows you the hook entry** it will add to this project's `.claude/settings.local.json`, and asks before writing it. Everything else in the file stays as it is. Use `-global` to add it to `~/.claude/settings.json` for every project instead.
3. **Checks the policy** and prints its rules.

**3. Restart Claude Code** so it loads the hook. That's it.

To try it without touching your own setup first, run `./scripts/demo-personal.sh` from a checkout of this repository. It sets everything up in a temporary folder and feeds the hook a dozen recorded tool calls.

## What the starter policy does

| The agent wants to | What happens |
|---|---|
| Read or search files | Goes ahead |
| Edit or create a file in the project | Goes ahead (Claude Code may still ask, by its own settings) |
| Edit a file outside the project | Asks you |
| Change a file through a symlink | Asks you: a link can be swapped between the check and the write |
| Run `git status`, `git diff`, `git log`, `git show`, `ls`, `pwd` | Goes ahead, if it's only that command |
| Run any other command, or anything with `;`, `&&`, `\|`, `$(…)` or a redirect | Asks you |
| Read or write `.env` files, SSH keys, cloud credentials | Blocked, and Claude is told why |
| Change Claude Code's settings, or ConsequenceOS's own policy and log | Blocked |
| Use an MCP tool you haven't listed | Asks you |
| An MCP server wrapped with `-stdio` asks you for a password, key or seed phrase | Blocked: the server is told you declined |

Tests and builds ask because they run code the agent can edit. If you trust that, allow them.

## Seeing what happened

```bash
consequenced -hook claude-code -log            # the last 20 decisions
consequenced -hook claude-code -log -n 100
consequenced -hook claude-code -verify-audit   # check nobody edited the log
```

The log records each call's tool, the rule that decided it, its consequence score and the outcome: `forwarded` (let through to Claude Code), `asked_user` or `blocked`. Arguments are stored only as a hash, so file contents and commands never reach the log. That keeps it safe to keep, but the log can't show you which command it was.

## Changing the rules

Edit `~/.consequence/claude-code.yaml`. Rules are checked top to bottom and the first match wins. After each change, run:

```bash
consequenced -hook claude-code -check
```

It prints the rules and warns about risky ones. To try a change without being interrupted, put `mode: observe` at the top of the file. Every call then goes ahead, and the log records which ones the policy would have stopped. `consequenced -report` sums them up. Take it out once that looks right.

Two habits keep the policy safe:

- **Loosen by allowing, not by deleting deny rules.** To let the agent run your tests, add `"go test ./..."` to the commands in `commands-that-only-look`, rather than removing `other-commands`.
- **Keep `compound: false` on shell allow rules.** Without it, `go test ./...; rm -rf ~` passes as `go test ./...`. `-check` warns if it's missing.

Some examples:

```yaml
  # Run the tests without asking, only when the command is just that.
  - name: tests
    tool: Bash
    when:
      - { arg: command, op: like, value: ["go test ./...", "npm test"] }
      - { arg: compound, op: eq, value: false }
    action: allow

  # Ask before every command once 50 have run in an hour.
  - name: busy-agent
    tool: Bash
    limit: { max: 50, per: 1h }
    action: ask

  # Never touch production configs, whatever the path looks like.
  - name: no-prod-config
    tool: "*"
    when: { arg: file_path, op: like, value: "*/deploy/prod/*", fold: true }
    action: deny
```

The full reference is in [Guarding Claude Code](claude-code.md): what each argument means, how paths are resolved, and what the hook can't protect against.

## Other agents and MCP servers

- **An MCP server with a token** (GitHub, Linear and so on): run `consequenced` in front of it with `upstream_auth_env`, so ConsequenceOS holds the token and the agent never sees it. See [Hosted MCP servers](../README.md#hosted-mcp-servers).
- **A local MCP server** started by your agent: put `consequenced -stdio --` before its command in the agent's MCP config. It uses the same policy and log as the hook, and asks you with `consequenced -approve`. It also pins each of the server's tools the first time it's listed: if an update changes what a tool says it does, the agent doesn't see the new version and its calls ask, until you read the change with `consequenced -accept-tool <tool>`. `consequenced -tools` lists them. See [Local MCP servers](../README.md#local-mcp-servers) and [Tool definitions](../README.md#tool-definitions).
- **Cursor and other coding agents** have their own hook formats. Each will get its own `-hook <name>`, on the same policy engine.
