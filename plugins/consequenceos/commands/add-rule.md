---
description: Draft a ConsequenceOS rule and its tests from plain words, check them, and show where to paste them
argument-hint: <what the rule should do, in plain words>
---

The person wants a ConsequenceOS rule that does this: $ARGUMENTS

Their policy is `~/.consequence/claude-code.yaml` (or the file `$CONSEQUENCEOS_POLICY` names). Don't open it, with Read or with the shell: ConsequenceOS keeps Claude out of its own folder, on purpose, so the Read tool is blocked and a shell `cat` would cost the person an extra approval. The check in step 3 prints every rule, in order, with yours in place, which is all you need. You can't change the policy either: you draft and check the rule, and the person pastes it in. Don't try another way to write the file.

1. **Understand the request.** New rules go in the policy's "Your rules" section: after the rules that protect secrets and the guard, and before the defaults. If the request is unclear in a way that changes the rule (which commands, which folders), ask one short question first.

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

3. **Write a test for each rule**: a call the rule should decide, and the decision it should get. The person's tests require one for every rule, so without them `/consequenceos:check` fails. Use the same paths as their existing tests, which use `/home/you/project` for the project:

   ```yaml
   - name: editing a migration asks
     tool: Edit
     args: { file_path: /home/you/project/db/migrations/001_init.sql, old_string: a, new_string: b }
     want: ask
     rule: ask-before-editing-migrations
   ```

   Where it helps, add one for a call the rule should *not* catch, with the decision it gets instead (`rule:` then names the rule that decides it).

4. **Check them, with one shell command.** Run this with the Bash tool: your rules, a line `--- tests ---`, then your tests. It's the only command you need, so the person approves just once:

   ```
   bash "${CLAUDE_PLUGIN_ROOT}/bin/consequenceos" try <<'EOF'
   - name: ...
   --- tests ---
   - name: ...
   EOF
   ```

   It puts the rules in the "Your rules" section of a copy of the policy, checks the copy, and prints every rule in the order they're checked. Then it adds the tests to a copy of the policy's tests and runs them all against that copy. Neither the policy nor its tests is touched. Read the rule list: if an earlier rule already decides the calls yours is about, yours never runs, so say so. Fix whatever fails, including warnings, and try again.

5. **Show the person** two `yaml` code blocks: the rules, and the tests. Say in one sentence what the rules do, and in one more how they could surprise them (what they let through, or what they now ask about). Tell them to paste the rules on the line just above `# ---- End of your rules ----` in `~/.consequence/claude-code.yaml`, the tests at the end of `~/.consequence/claude-code.test.yaml`, then run `/consequenceos:check`.
