# Shadow score: an experiment

The tools map scores a tool, not a call: deleting one contact and deleting 250 score the same (see [What it doesn't cover](consequence.md#what-it-doesnt-cover)). One proposed fix multiplies the tool's score, at call time, by the consequence of the specific call: how many records it touches, and whether data leaves the company.

This experiment checks that idea before anything depends on it. Nothing in the gate uses it.

```bash
make shadow-score
# or, with another policy or weights:
go run ./cmd/shadow-score -cases examples/shadow-score/cases.yaml \
  -spec examples/shadow-score/spec.yaml \
  -config examples/shadow-score/consequence.arg-rules.yaml
```

`cmd/shadow-score` decides each case twice, with the same policy: once on the tools map's score (**today**), and once on the context score (**context**). It prints both next to `want:`, the decision we'd actually want, and lists every multiplier with its reason.

## How the context score works

`internal/shadowscore`. The spec names, per tool, the argument that holds its records (a list or a number) and the one that holds its destination (email addresses, URLs or domains).

| Fact | Multiplier (default) |
|---|---|
| 1 record | ×1 |
| 2 to 99 records | ×1.25 (`few`) |
| 100 or more, or a count that can't be read | ×1.5 (`many`) |
| every destination inside `internal_domains` | ×1 (`internal`) |
| any destination outside, or one that can't be read | ×1.5 (`external`) |

Context score = tools-map score × every multiplier, rounded, at most 100. Facts that can't be read count as the worse case. Only top-level arguments are read.

## Results (2026-11-25)

The cases are pairs: one record vs. many, and an internal vs. an external destination. The policy (`examples/shadow-score/consequence.yaml`) puts the hard rule first, then `score gte 70 → ask` for the calls it leaves open, then the convenience allow.

| Case | Want | Today | Context |
|---|---|---|---|
| delete one contact | allow | allow (40) | allow (40) |
| delete 250 contacts | ask | allow (40) | allow (60) |
| delete every contact | deny | deny, hard rule | deny, hard rule |
| export 3 contacts to ops@acme.com | allow | allow (0) | allow (0) |
| export 3 contacts to a gmail address | ask | allow (0) | allow (0) |
| email a teammate | allow | ask (80) | ask (80) |
| email a customer | ask | ask (80) | ask (100) |

**The context score changed no decision.** Four of the 7 cases are right either way and 3 are wrong either way. The reasons:

1. **A read stays at 0.** The export tool only reads the CRM, so its base score is 0, and 0 times anything is 0. The score can't see that the export sends 3 contacts to a gmail address, though that's the most dangerous call here.
2. **Multipliers of 1 or more can only raise a score.** Sending a teammate an email stays at 80. Bringing it under 70 would take an internal weight below 0.875, a number picked to get one result.
3. **The thresholds come down to the weights.** The bulk delete reaches 60, under 70. With `many: 1.75` it reaches exactly 70 and asks. That weight was chosen because it lands on the threshold, which is the hard part to explain when someone asks why a call went through.

**Rules on the arguments fix 2 of the 3, with no score at all.** `consequence.arg-rules.yaml` adds two rules: ask for an export that goes outside (`to not_like "*@acme.com"`) and allow email when every recipient is internal (`to.* like "*@acme.com"`). That gives 6 of 7 right. Anyone can read each of those decisions straight from the rule that made it.

**The one case rules can't reach is a count.** Conditions can't test how long a list is, so no rule can say "more than 100 contacts". That's a gap in the policy language, and the narrowest fix for it is a condition on list length, not a weighted score.

## What follows

- Keep hard rules first. A score, if one is used, decides only the calls no rule matches, as `default_allow_below` and the `score` fact already do.
- Prefer a fact a rule can test (a record count, internal vs. external) over a multiplier folded into the score. A rule that names the fact explains itself.
- Before anyone relies on argument-dependent scores, record each assessment's reasons in the audit log. Today the log keeps only the score.
- Rerun this with real tools and real cases when there are some. A run where "score fixes it" outnumbers "both wrong" is the evidence to look for.
