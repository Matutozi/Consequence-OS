---
description: Draft a ConsequenceOS rule from plain words, check it, and show where to paste it
argument-hint: <what the rule should do, in plain words>
---

The person wants a ConsequenceOS rule that does this: $ARGUMENTS

Their policy is `~/.consequence/claude-code.yaml` (or the file `$CONSEQUENCEOS_POLICY` names). You can read it, but you can't change it: ConsequenceOS blocks Claude from editing its own policy, on purpose. You draft and check the rule; the person pastes it in. Don't try another way to write the file.

1. **Read the policy.** Look at the rules already there, and find the section between `# ---- Your rules ----` and `# ---- End of your rules ----`. New rules go there: after the rules that protect secrets and the guard, and before the defaults. If the request is unclear in a way that changes the rule (which commands, which folders), ask one short question first.

2. **Draft the smallest rule that does it**, in this language:

   ```yaml
   - name: a-short-name             # shown when the rule decides a call
     tool: Bash                     # Claude Code's tool name; globs work: "*", mcp__github__*
     when:                          # optional; every condition must hold
       - { arg: command, op: like, value: ["go test ./...", "npm test"] }
       - { arg: compound, op: eq, value: false }
     action: allow                  # allow, ask or deny
   ```

   - **Arguments** are the tool's input: `command` for `Bash`; `file_path` for `Edit`, `Write` and `Read`; and so on. ConsequenceOS adds `program` (a shell command's first word), `compound` (true when a command chains or redirects: `;` `&&` `|` `$(` `>`), `in_project` (true for a file inside the project) and `via_symlink`. File paths arrive absolute, with symlinks resolved.
   - **Operators:** `eq` `ne` `gt` `gte` `lt` `lte` `in` `not_in` `like` `not_like`. `like` takes globs (`*`, `?`) and a list of them. `fold: true` ignores letter case.
   - **Limits:** `limit: { max: 50, per: 1h }` makes the rule apply once more than 50 matching calls happen in an hour.
   - **Time windows:** `during:` or `outside: { days: [mon, tue, wed, thu, fri], hours: "09:00-17:00", timezone: Africa/Lagos }`.
   - **Allow what you trust; don't deny what you fear.** To let a shell command through, allow that exact command and require `compound: false`, so `go test ./...; rm -rf ~` doesn't pass as `go test ./...`. A deny rule on a command's text is easy to get around (`git push -f` instead of `git push --force`); every command that no rule allows already asks.

3. **Check it.** Run this with the Bash tool, with your rule between the `EOF` lines:

   ```
   bash "${CLAUDE_PLUGIN_ROOT}/bin/consequenceos" try <<'EOF'
   - name: ...
   EOF
   ```

   It puts the rule in the "Your rules" section of a copy of the policy and checks the copy; the policy itself isn't touched. Fix whatever it reports, including warnings, and check again.

4. **Show the person** the rule in a `yaml` code block. Say in one sentence what it does, and in one more how it could surprise them (what it lets through, or what it now asks about). Tell them to paste it on the line just above `# ---- End of your rules ----` in their policy, then run `/consequenceos:check`.
