# Guarding Claude Code

Claude Code edits files and runs shell commands with its own built-in tools, not through MCP, so the proxy never sees them. The hook mode closes that gap. Claude Code runs `consequenced -hook claude-code` before every tool call, and ConsequenceOS checks the call against your policy:

- **deny:** the call is blocked, and Claude is told which rule blocked it.
- **ask:** Claude Code asks you, in its usual permission prompt, with the rule and the consequence score.
- **allow:** ConsequenceOS stays silent, and Claude Code's own permission settings decide as usual. It can only make a call stricter, never looser.

Every call is recorded in a hash-chained audit log on your machine. Nothing leaves it.

## Setting it up

You need the `consequenced` binary on your `PATH` (see [Install](../README.md#install)). Linux and macOS only.

**1. A policy.** Save this as `~/.consequence/claude-code.yaml`, and adjust it:

```yaml
state_dir: ~/.consequence/state         # the audit log and limits, kept between calls
local_agent: { id: claude-code, owner_id: me }

tools:                                  # how serious each tool is; unlisted tools count as irreversible
  Read: read
  Grep: read
  Glob: read
  Edit: reversible
  Write: reversible
  Bash: irreversible

rules:
  # Keep the agent away from the guard itself.
  - name: guard-the-guard
    tool: "*"
    when: { arg: file_path, op: like, value: ["*/.claude/settings*.json", "*/.consequence/*"] }
    action: deny
  - name: no-secrets
    tool: "*"
    when: { arg: file_path, op: like, value: ["*/.env", "*/.env.*", "*/.ssh/*"], fold: true }
    action: deny
  # A link could be swapped for one to a secret between the check and the write.
  - name: writes-through-links
    tool: "*"
    when: { arg: via_symlink, op: eq, value: true }
    action: ask
  - name: edits-in-the-project
    tool: Edit
    when: { arg: in_project, op: eq, value: true }
    action: allow
  - name: safe-git
    tool: Bash
    when:
      - { arg: command, op: like, value: ["git status*", "git diff*", "git log*"] }
      - { arg: compound, op: eq, value: false }
    action: allow
  - name: shell
    tool: Bash
    action: ask
```

Check it with `consequenced -hook claude-code -config ~/.consequence/claude-code.yaml -check`. It prints the rules and warns about risky ones.

**2. The hook.** Add this to `~/.claude/settings.json` for every project, or to a project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "consequenced -hook claude-code -config ~/.consequence/claude-code.yaml",
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

`onFailure: "block"` matters. Without it, Claude Code lets a tool call run when its hook can't start, crashes or times out. ConsequenceOS blocks every failure it can see by exiting with code 2, but it can't catch a hook that never ran, such as a typo in the command. The setting needs Claude Code v2.1.295 or later.

## What the policy sees

- **Tool names** are Claude Code's own: `Bash`, `Edit`, `Write`, `Read`, `Grep`, `Glob`, `WebFetch`, and `mcp__<server>__<tool>` for MCP tools. Rules match them like any tool name, globs included.
- **Arguments** are the tool's input: `command` for `Bash`, `file_path` for `Edit`, `Write` and `Read`, and so on.
- **File paths are resolved first.** For the file tools, `file_path` (or `path`, or `notebook_path`) is made absolute against Claude Code's working directory and cleaned, with symlinks resolved. So `sub/../.env`, and a link pointing at `.env`, both reach the policy as the real `.env`.

The hook also adds these arguments. Each replaces anything the agent sent under the same name, in any letter case.

| Argument | Tools | What it is |
|---|---|---|
| `program` | `Bash`, `PowerShell` | The command's first word after any `VAR=value` assignments: `git` for `GIT_PAGER=cat git log` |
| `compound` | `Bash`, `PowerShell` | `true` when the command holds `;` `&` `\|` `` ` `` `$(` `<` `>` `(` `)` or a line break, so it could run more than one program or redirect output |
| `in_project` | file tools | `true` when the resolved path is inside the project (`$CLAUDE_PROJECT_DIR`, or the working directory) |
| `via_symlink` | file tools | `true` when any existing part of the path is a symlink, or the tool gave no path |

## Allow-list shell commands, don't deny-list them

A deny rule on `git push --force` misses `git push -f`, `git  push --force` and `sh -c 'git push --force'`. No pattern catches every way to write a command. An allow rule fails closed instead: a command it doesn't recognize falls through and asks. So allow the commands you trust, **only when `compound` is false**, and let everything else ask. Without that condition, `git status; rm -rf ~` passes as `git status`. `-check` warns about an allow rule on `Bash` that doesn't require `compound: false`, and about deny rules that match commands with `like`.

## The audit log and limits

- **Outcomes.** Each call is recorded as `forwarded` (let through to Claude Code), `blocked`, or `asked_user`. ConsequenceOS doesn't learn your answer to an ask.
- **Contents.** Arguments are stored only as a hash, so a file's contents never reach the log.
- **Checking it.** Run `consequenced -hook claude-code -config ~/.consequence/claude-code.yaml -verify-audit`.
- **Limits** count a call when it is allowed or asked, whatever you answered, so they over-count rather than under-count. For example, `{ limit: { max: 20, per: 1h }, action: ask }` on `Bash` asks about every command once 20 have run in an hour.

## Failing closed

Any failure blocks the call, and the reason shown to Claude says what went wrong. That includes a config that won't load, a state directory another process holds for more than 10 seconds, input it can't read, or an internal error. Claude Code runs tool calls in parallel, and each hook takes the state directory's lock in turn.

## What this doesn't cover

- **It isn't a sandbox.** Claude Code enforces the hook, not the operating system. Anyone who can edit the settings file can remove it. The starter rules make that hard for the agent, but not impossible.
- **Shell matching is text matching.** `program` and `compound` make allow-lists safe for simple commands. They don't understand what a program does with its arguments: `git log --output=FILE` writes a file. Keep allow-lists to commands you would run without reading them.
- **Symlinks are resolved when the hook decides.** A link could still change before the tool runs. That's why writes through links ask, and why a starter rule asks for every `Bash` command, `ln` included.
- **Permission modes.** In `bypassPermissions` mode, a deny still blocks. Whether Claude Code still shows the prompt for an ask isn't documented, so don't rely on it there.
