# Plugin Scoring Rubric (2026 Q2)

Each of the 50 ideas is scored out of 100.

## Weighted Criteria
- Operator value: 35
- Reliability and deterministic behavior: 25
- Integration simplicity with PumpBin templates: 20
- OPSEC and artifact quality impact: 10
- Build and maintenance cost (lower cost gets higher score): 10

## Scoring Method
For each criterion, assign 1-10.
Final score formula:

Final = (Value * 3.5) + (Reliability * 2.5) + (Integration * 2.0) + (OPSEC * 1.0) + (Cost * 1.0)

## Selection Rules
- Must not collide with existing crate names.
- Must keep contract compatibility with PumpBin function signatures.
- post_binary candidates must keep output safe and deterministic.
- Top 5 should cover practical operator workflows, not only novelty.
