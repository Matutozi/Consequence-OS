---
description: Check your ConsequenceOS rules, and run their tests
---

Check the person's ConsequenceOS policy. Run this with the Bash tool. ConsequenceOS asks the person first, as it does for any shell command it doesn't know:

```
bash "${CLAUDE_PLUGIN_ROOT}/bin/consequenceos" check
```

It prints the rules in the order they're checked, any warnings about them, and then the results of the policy's tests.

Then tell the person, briefly and in plain words:

- **The rules**, as a short table in the order they're checked: name, what it matches, and whether it allows, asks or denies. The first rule that matches a call decides it.
- **Warnings**, if any, and what each means for them.
- **The tests.** A failing test means the policy now decides some call differently from what its test expects, usually because a rule was added or changed. Say which call, what it gets now, and whether that looks intended. If it was intended, the test should be changed to match.

Don't edit the policy or its tests, and don't try another way to change them: ConsequenceOS blocks Claude from changing its own policy, on purpose. If something should change, show the person the exact change and where it goes, and they make it.
