# Probability Model

## Overview

PredictiveAttackPath uses a weighted co-occurrence graph built from MITRE ATT&CK data to predict what an attacker will do next.

## Graph Construction

- **Nodes**: every ATT&CK Enterprise technique (691 including sub-techniques)
- **Edges**: created when at least one APT group uses both techniques
- **Edge weight**: the number of distinct groups sharing both techniques (max observed: 74)

## Scoring

Given a set of detected techniques D:

```
For each technique d in D:
    For each neighbor n of d (where n is not in D):
        score[n] += edge_weight(d, n) / max_weight_in_graph
```

Scores are normalized to [0.0, 1.0].

## Attribution

Groups are scored by a weighted combination:

```
score = 0.6 × (|overlap| / |detected|) + 0.4 × (|overlap| / |group_playbook|)
```

The top 3 matching groups contribute to the attribution boost.

## Attribution Boost

Predicted techniques that appear in a top-attributed group's playbook receive a 1.5× score multiplier. This focuses predictions on the specific group's known tradecraft.

## Confidence Adjustment

Base confidence (from the regex pattern library) is adjusted upward when multiple distinct patterns match within the same log, or when matches span multiple lines.
