# Consequence

Before the policy decides on a call, ConsequenceOS assesses it: what the call would affect, and how badly. Rules can match on that assessment as well as on the tool's name and arguments, and the default for calls no rule matches comes from it.

## The assessment

| Fact | What it is | Today, from the tools map |
|---|---|---|
| `score` | 0 (harmless) to 100 (worst), an integer | read 0, reversible 40, irreversible 80 |
| `reversibility` | `read`, `reversible`, `compensable` or `none` | the tool's level; `irreversible` is `none` |
| `blast_radius` | how many things depend on what the call touches | unknown |
| `data_classes` | kinds of data touched, such as `payment`, `personal`, `auth` | none |
| `owners` | who owns what the call touches, such as a CODEOWNERS team | none |
| `targets` | what the call acts on, such as `path:internal/billing/` | none |
| `source` | where the assessment came from: `config` or `map` | `config` |

Every assessment also carries **reasons**: one plain sentence for each thing that set the score, such as "payments.refund is listed as irreversible in the tools map." Approvers see them on the approval page, and `consequenced -tool` prints them.

A tool that isn't in the tools map scores 80, as irreversible. A resource or prompt that isn't listed scores 0, as a read.

## Rules on consequence

A rule's `consequence:` block is written like `when:`, with a fact in place of an argument. Every condition must hold, along with the rule's tool pattern, `when:`, schedule and limit.

```yaml
rules:
  - name: high-consequence-asks
    tool: "*"
    consequence: { arg: score, op: gte, value: 70 }
    action: ask
  - name: nothing-irreversible-at-weekends
    tool: "*"
    consequence: { arg: reversibility, op: eq, value: none }
    during: { days: [sat, sun], timezone: Africa/Lagos }
    action: deny
```

- **Numbers** (`score`, `blast_radius`) take every operator.
- **Text** (`reversibility`, `source`) takes `eq`, `ne`, `in` and `not_in`. Values are checked when the config loads, so `irreversible` is refused with a note that it's called `none`.
- **Lists** (`data_classes`, `owners`, `targets`) take `eq`, `ne`, `in` and `not_in`. `eq` and `in` match when **any** item matches, so `{ arg: data_classes, op: in, value: [payment] }` matches every call that touches payment data, whatever else it touches. `ne` and `not_in` match when **no** item does.
- **A missing fact never matches,** like a missing argument. A blast radius of 0 means unknown and counts as missing, as does an empty list. A score of 0 is a real score.

**Allow on lists with `not_in`.** An allow rule with `in` on a list fact lets through a call that touches the listed data *and* anything else. To allow only calls that touch none of the sensitive data, write `{ arg: data_classes, op: not_in, value: [payment, personal, auth] }`. `consequenced -check` warns about allow rules that use `eq` or `in` on a list fact.

**Put broad deny rules first.** Rules match top to bottom. A `tool: "*"` deny placed after an allow for the same tool never sees that tool's calls.

## The default

With no matching rule, a call scoring under `default_allow_below` is allowed, and everything else asks. The default threshold is 20, which gives the same results as before scores existed: reads (0) are allowed, everything else (40 and up) asks. Set it to 0 to allow nothing by default.

```yaml
default_allow_below: 20
```

## Where the score goes

- **Audit log:** each entry records the score. The hash chain covers it. Entries from before scores existed still verify, and show no score.
- **Approvals:** the approval page shows the score and the reasons above the arguments.
- **Receipts:** not yet. Receipt v1 has room for the score, and the server will fill it once it starts issuing v1.

## What it doesn't cover

- **Arguments.** The tools map scores a tool, not a call. Deleting one row and deleting every row score the same. Use `when:` conditions on the arguments for that, or a consequence map once it exists.
- **The facts beyond score and reversibility.** `blast_radius`, `data_classes`, `owners` and `targets` are always empty with the tools map alone. Rules on them are valid but never match until a consequence map supplies them.
- **Compensable actions.** A `compensable` assessment scores as irreversible, until undo contracts can show the compensation really runs.
- **Reasons in the audit log.** Only the score is logged. A consequence map may build reasons from the arguments, which the log never holds.
