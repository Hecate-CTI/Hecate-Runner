# Continuous synthetic replay

Continuous replay evaluates independent, source-shaped positive and benign cases.
It never executes commands or expands rules. A synthetic pass does not establish
live detection or an independent holdout score.

Run `hecate-runner replay-check H-0038 --workspace /path/to/private-workspace`.
The command reads files only; it does not notify Slack. Exit codes are 0 for all
checks passed, 1 for errors/failures, and 2 when any rule lacks current cases.

Store private cases in `.hecate/replay_cases/H-0038.json`:

```json
{
  "schema": 1,
  "hunt_id": "H-0038",
  "rules": {
    "dns.yml": {
      "rule_sha256": "SHA256 of the reviewed rule file",
      "source_reference": "Primary report URL or internal evidence reference",
      "positive": [{"QueryName": "reported-threat.invalid"}],
      "benign": [{"QueryName": "example.com"}]
    }
  }
}
```

Write cases from the source procedure and legitimate alternatives, independently
of the rule predicates. Each rule needs at least one positive and one benign case.
These examples establish only the behavior tested; expand them with relevant
variants and near misses. Review the cases again whenever rule bytes change.
Missing or stale cases are **not assessed**, not detection misses. Malformed,
overlapping or explicitly mismatched platform/category cases produce errors.

Reports in `.hecate/replay_results/` list each rule's pass, failure, error or
unassessed status, required-case counts and confusion matrix. Predicate-derived
checks appear separately as `sanity_status` and never rescue a failed independent
case. Sample counts are positive and benign **rule-event evaluations**, so an
event used against two rules counts twice.

The background sweep sends Slack alerts only for changed failures/errors. The
report includes unassessed counts; these do not generate repeated tuning alerts.
Old tuning suggestions are not replay inputs and should be archived after review.
The separate analyst tuning workflow remains available. Automatic miss-based
expansions reject synthetic/placeholder evidence, already-matching events,
evaluation errors, incomplete recall and regressions against the fixed benign
smoke baseline. That baseline is limited; it cannot authorize production tuning.
