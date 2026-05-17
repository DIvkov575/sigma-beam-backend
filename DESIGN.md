# Sigma → Apache Beam Backend (`sigma_beam`)

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement this plan task-by-task. Steps use `- [ ]` syntax.

**Goal:** Run Sigma detections (single-event AND correlation) as a streaming Apache Beam pipeline on Dataflow, replacing beaver's current single-event-only codegen path.

**Architecture:** A reusable Python package (`dataflow/sigma_beam/`) that exposes Beam `PTransform`s for single-event and correlation rules. Rules are loaded at worker startup from a GCS prefix (uploaded by `beaver deploy`). Single-event evaluation is in-process; correlation rules use `GroupByKey + Windowing` (count rules) or stateful `DoFn`s with event-time timers (temporal rules). Matches go to a new `beaver-alerts` Pub/Sub topic, fanned out to a BigQuery `alerts` table by an attached subscription, mirroring the existing `events` flow. Parse errors and per-rule evaluation errors go to a `beaver-dlq` topic.

**Tech Stack:** Apache Beam 2.x (Python), pySigma ≥0.11 (for rule parsing + correlation AST), Dataflow runner, Pub/Sub I/O, BigQuery Storage Write API, Cloud Monitoring metrics.

---

## Why this design

### Why pySigma for parsing, but custom evaluation

pySigma's `Backend` base class is geared toward emitting strings (query languages). We want **runtime evaluation**, not string output. So we use pySigma for what it's good at — parsing YAML, expanding modifiers, validating correlation rule shape, applying processing pipelines for log-source field mapping — and we walk its parsed `SigmaRule.detection` / `SigmaCorrelationRule` trees ourselves to build a tree of callables and `DoFn`s.

This is materially cleaner than subclassing `TextQueryBackend` to emit Python source and `exec()`-ing it.

### Why interpreter over codegen

Beaver currently codegens a `detections.py` module from Rust. That works for single-event but is awkward for correlation (state, windowing, timers). An interpreter:
- Loads rules from GCS at worker startup → rule edits don't require a pipeline redeploy (just a job restart, or in-place update).
- Lets pySigma own all parsing concerns (modifiers, value types, log-source mapping).
- Per-event cost is negligible vs. Pub/Sub deserialization.

We keep beaver's existing `sigma::generate_detections` Rust step — but instead of generating Python source, it stages compiled rules (the cleaned/expanded YAML pySigma already produces) into a directory that `beaver deploy` uploads to `gs://<bucket>/rules/`.

### Why split single-event from correlation in the pipeline graph

Single-event rules can run as a stateless `ParDo`. Correlation rules need windowing and (for temporal) state. Forcing both through a stateful DoFn would waste resources on the 95% of rules that don't need it.

Pipeline shape:

```
Pub/Sub → ParseJSON → [DLQ on parse fail]
                  ↓
           SingleEventDetect (ParDo, fans through all single-event rules)
                  ↓
        ┌─────────┴──────────┐
        ↓                    ↓
   AlertsSink         CorrelationFanout (one branch per correlation rule)
                              ↓
                     EventCount | ValueCount | Temporal | TemporalOrdered
                              ↓
                          AlertsSink
```

### Why Pub/Sub alerts topic + BQ subscription

Mirrors existing event flow, gives us:
- Decoupled fan-out (notifications, SOAR, dashboards).
- Free queryability via BQ.
- Backpressure protection.

---

## File structure

```
dataflow/sigma_beam/
  __init__.py
  loader.py            # Load+parse rules from GCS prefix, build Ruleset
  ruleset.py           # Ruleset dataclass: single_event[], correlation[]
  field_access.py      # Dotted/JSON-pointer field access into nested dicts
  predicates.py        # equals, contains, startswith, endswith, re, cidr, gt/lt
  modifiers.py         # Apply pySigma modifiers to value matchers
  conditions.py        # Walk pySigma ConditionAND/OR/NOT/FieldEquals → Callable[[dict], bool]
  single_event.py      # SingleEventDetect PTransform (fanout over all single-event rules)
  correlation/
    __init__.py
    event_count.py     # event_count rule DoFn + windowing
    value_count.py
    temporal.py        # unordered temporal: stateful DoFn
    temporal_ordered.py
  alerts.py            # Alert dataclass, serialization, AlertsSink PTransform
  dlq.py               # Dead-letter helpers
  metrics.py           # Beam Metrics wrappers (per-rule counters)
  errors.py            # Custom exceptions

dataflow/pipelines/
  correlation_pipeline.py   # New main pipeline (replaces detections_template.py over time)

dataflow/tests/sigma_beam/
  test_field_access.py
  test_predicates.py
  test_modifiers.py
  test_conditions.py
  test_loader.py
  test_single_event.py
  test_event_count.py
  test_value_count.py
  test_temporal.py
  test_temporal_ordered.py
  test_alerts.py
  test_dlq.py
  test_e2e_direct.py        # End-to-end on DirectRunner
  fixtures/
    rules/                  # Hand-written Sigma YAML for tests
    events.jsonl

dataflow/sigma_beam/requirements.txt   # pysigma>=0.11, apache-beam[gcp], google-cloud-storage
```

### Rust-side changes

- `src/lib/sigma.rs`: after `pysigma` compilation, stage the cleaned rules to `<config>/.beaver/rules/` for upload.
- `src/lib/gcs.rs` (or new `rules_upload.rs`): upload `<config>/.beaver/rules/*.yml` to `gs://<bucket>/rules/` during deploy.
- `src/lib/resources.rs`: add `alerts_topic_id`, `alerts_subscription_id`, `alerts_table_id`, `dlq_topic_id`, `rules_gcs_prefix`.
- `src/commands/deploy.rs`:
  - New step: create `beaver-alerts` topic + BQ-push subscription + `alerts` BQ table.
  - New step: create `beaver-dlq` topic.
  - New step: upload rules to GCS.
  - Modify Dataflow step: launch `correlation_pipeline` instead of `detections_template`, pass `--alerts_topic`, `--dlq_topic`, `--rules_uri` args.
- `src/commands/destroy.rs`: matching deletion steps.
- `src/lib/dashboard.rs`: add tiles for `custom.googleapis.com/sigma_beam/matches` and `…/errors`.

---

## Open design choices (decide before Task 1)

1. **Pub/Sub message envelope.** Beaver's existing flow assumes JSON event in the body. Confirm we keep that.
2. **Alert schema.** Proposed: `{rule_id, rule_title, severity, fired_at, window_start, window_end, correlation_key, matched_events: [{...}]}`. For single-event, `window_*` null and `matched_events` has one record.
3. **Late data.** Default allowed lateness: 5 minutes. Configurable per rule via a non-standard `beaver.allowed_lateness_seconds` field in rule metadata.
4. **Rule reload.** v1: rules baked into job at launch; rule changes require `beaver deploy` (re-uploads rules + restarts Dataflow job in-place). v2: side input from GCS poll.
5. **State TTL for temporal rules.** Hard cap: 2× window size. Prevents pathological key growth.
6. **Cardinality guardrails.** Refuse to launch if any `event_count`/`value_count` rule groups by an unbounded-cardinality field (e.g., `user_agent`) without an explicit `beaver.allow_high_cardinality: true` annotation. Implemented as a static linter at load time.

---

## Tasks

Each task ends with a commit. Run tests under `dataflow/` with `pytest dataflow/tests/sigma_beam -v`. Use Beam's `DirectRunner` for tests.

### Task 1: Scaffold package + CI

**Files:**
- Create: `dataflow/sigma_beam/__init__.py` (empty)
- Create: `dataflow/sigma_beam/requirements.txt`
- Create: `dataflow/tests/sigma_beam/__init__.py`
- Modify: `dataflow/requirements.txt` (add pysigma)

- [ ] Add deps: `apache-beam[gcp]>=2.55`, `pysigma>=0.11`, `pyyaml`, `google-cloud-storage`.
- [ ] Verify `pytest dataflow/tests/sigma_beam -v` runs (0 collected is fine).
- [ ] Commit: `feat(sigma_beam): scaffold package`.

### Task 2: Field access

**Files:**
- Create: `dataflow/sigma_beam/field_access.py`
- Create: `dataflow/tests/sigma_beam/test_field_access.py`

- [ ] Write failing tests for: flat key, dotted nested key (`a.b.c`), array index (`logs.0.message`), missing key returns `MISSING` sentinel (NOT `None`), case-sensitive default.
- [ ] Implement `get_field(event: dict, path: str) -> Any | Missing`.
- [ ] Commit.

### Task 3: Primitive predicates

**Files:**
- Create: `dataflow/sigma_beam/predicates.py`
- Create: `dataflow/tests/sigma_beam/test_predicates.py`

- [ ] Implement + test: `equals`, `contains`, `startswith`, `endswith`, `re_match` (compiled lazily), `cidr_contains` (using `ipaddress`), `gt`, `gte`, `lt`, `lte`, `in_list`.
- [ ] Each predicate handles `MISSING` by returning False (never raise).
- [ ] Commit.

### Task 4: Modifier dispatch

**Files:**
- Create: `dataflow/sigma_beam/modifiers.py`
- Create: `dataflow/tests/sigma_beam/test_modifiers.py`

- [ ] Map pySigma modifier classes (`SigmaContainsModifier`, `SigmaStartswithModifier`, `SigmaRegularExpressionModifier`, `SigmaCIDRModifier`, `SigmaBase64Modifier`, `SigmaWindowsDashModifier`, etc.) to a predicate factory.
- [ ] Tests: each modifier produces correct predicate behavior on `["foo", "bar"]` value lists (OR-semantics).
- [ ] Out of scope for v1: `|fieldref`, `|expand`. Raise `UnsupportedModifier`.
- [ ] Commit.

### Task 5: Condition tree walker

**Files:**
- Create: `dataflow/sigma_beam/conditions.py`
- Create: `dataflow/tests/sigma_beam/test_conditions.py`

- [ ] `compile_condition(rule: SigmaRule) -> Callable[[dict], bool]`.
- [ ] Walk pySigma `ConditionAND`/`OR`/`NOT`/`FieldEqualsValueExpression`/`FieldEqualsStringExpression`/`ValueExpression` (keyword search).
- [ ] Detection-item references resolved by name from `rule.detection.detections`.
- [ ] Tests: hand-built `SigmaRule` objects covering AND/OR/NOT, modifier chains, `1 of selection_*`, `all of selection_*`, keyword search, null/not-null.
- [ ] Commit.

### Task 6: Ruleset loader

**Files:**
- Create: `dataflow/sigma_beam/ruleset.py`
- Create: `dataflow/sigma_beam/loader.py`
- Create: `dataflow/tests/sigma_beam/test_loader.py`
- Create: `dataflow/tests/sigma_beam/fixtures/rules/single_event_basic.yml`
- Create: `dataflow/tests/sigma_beam/fixtures/rules/correlation_count.yml`

- [ ] `Ruleset` dataclass: `single_event: list[CompiledRule]`, `correlation: list[CompiledCorrelation]`.
- [ ] `CompiledRule(id, title, severity, predicate, source_yaml_hash)`.
- [ ] `CompiledCorrelation(id, title, severity, kind, window_seconds, group_by, threshold, referenced_rule_ids, ...)`.
- [ ] `load_from_gcs(prefix: str) -> Ruleset` using `google-cloud-storage`. Also `load_from_dir(path)` for tests.
- [ ] Static cardinality linter (refuses high-cardinality `group_by` without annotation).
- [ ] Tests: load 2-rule fixture (single-event + correlation), assert structure.
- [ ] Commit.

### Task 7: Single-event PTransform

**Files:**
- Create: `dataflow/sigma_beam/alerts.py`
- Create: `dataflow/sigma_beam/single_event.py`
- Create: `dataflow/sigma_beam/metrics.py`
- Create: `dataflow/sigma_beam/dlq.py`
- Create: `dataflow/sigma_beam/errors.py`
- Create: `dataflow/tests/sigma_beam/test_alerts.py`
- Create: `dataflow/tests/sigma_beam/test_single_event.py`
- Create: `dataflow/tests/sigma_beam/test_dlq.py`

- [ ] `Alert` dataclass + JSON serializer.
- [ ] `SingleEventDetect(rules)` PTransform: wraps a `ParDo` that yields `Alert`s tagged `'matches'` and errors tagged `'errors'`.
- [ ] Per-rule Beam counters: `matches_<rule_id>`, `errors_<rule_id>`, `evaluated`.
- [ ] DLQ: errors PCollection serialized as `{rule_id, error, event}` JSON, sent to DLQ topic via separate `WriteToPubSub`.
- [ ] Tests on `DirectRunner` with `TestPipeline`: assert tagged outputs, counters, error path.
- [ ] Commit.

### Task 8: `event_count` correlation

**Files:**
- Create: `dataflow/sigma_beam/correlation/__init__.py`
- Create: `dataflow/sigma_beam/correlation/event_count.py`
- Create: `dataflow/tests/sigma_beam/test_event_count.py`
- Create: `dataflow/tests/sigma_beam/fixtures/rules/event_count_login_failures.yml`

- [ ] `EventCountCorrelation(rule)` PTransform: `WithKeys(group_by)` → `WindowInto(FixedWindows(window_seconds), allowed_lateness=...)` → `CombinePerKey(CountCombineFn)` → `Filter(count >= threshold)` → emit `Alert`.
- [ ] Event-time from `event['timestamp']` (configurable field).
- [ ] Tests: 5 failed logins in 1 minute → 1 alert; 4 failed logins → 0 alerts; events across window boundary correctly bucketed.
- [ ] Commit.

### Task 9: `value_count` correlation

**Files:**
- Create: `dataflow/sigma_beam/correlation/value_count.py`
- Create: `dataflow/tests/sigma_beam/test_value_count.py`
- Create: `dataflow/tests/sigma_beam/fixtures/rules/value_count_distinct_dst.yml`

- [ ] Same shape as event_count but combine step uses `DistinctValuesCombineFn` over the `condition.field` value.
- [ ] Memory cap per key: refuse to track > 10k distinct values per key per window (emit error to DLQ if exceeded).
- [ ] Tests: 100 distinct destination IPs from one src in 5 min → 1 alert; 50 → none.
- [ ] Commit.

### Task 10: `temporal` correlation (unordered)

**Files:**
- Create: `dataflow/sigma_beam/correlation/temporal.py`
- Create: `dataflow/tests/sigma_beam/test_temporal.py`
- Create: `dataflow/tests/sigma_beam/fixtures/rules/temporal_recon_then_lateral.yml`

- [ ] Stateful DoFn keyed on `group_by`:
  - `BagStateSpec`: holds set of `(referenced_rule_id, event)` tuples seen so far.
  - `TimerSpec` (event-time): set to `event_time + window_seconds`; fires to clear state.
  - On element: add to bag. If bag contains at least one event for every referenced rule → emit `Alert`, clear state (or not — see below).
- [ ] Decision: "fire-and-suppress" semantics (clear after match) vs "fire-each-additional"; default fire-once-per-window.
- [ ] State TTL guardrail: max 2× window.
- [ ] Tests: ruleA then ruleB within 60s → 1 alert; only ruleA → 0; both but 70s apart → 0.
- [ ] Commit.

### Task 11: `temporal_ordered` correlation

**Files:**
- Create: `dataflow/sigma_beam/correlation/temporal_ordered.py`
- Create: `dataflow/tests/sigma_beam/test_temporal_ordered.py`
- Create: `dataflow/tests/sigma_beam/fixtures/rules/temporal_ordered_kill_chain.yml`

- [ ] Stateful DoFn with `ValueStateSpec[int]` (current position in sequence).
- [ ] On element: if matches `sequence[position]`, advance and append to bag; if at end → emit Alert. If matches `sequence[0]` from any state, restart bag (allow false starts).
- [ ] Out-of-order events within event-time window: buffer + sort on timer fire. Document this as expensive; encourage short windows.
- [ ] Tests: A→B→C within 60s → alert; A→C→B → no alert; A→B→A→C → alert.
- [ ] Commit.

### Task 12: Correlation fanout

**Files:**
- Create: `dataflow/sigma_beam/correlation/fanout.py`
- Create: `dataflow/tests/sigma_beam/test_correlation_fanout.py`

- [ ] `CorrelationDetect(ruleset)` PTransform: pre-filters input PCollection per correlation rule's referenced single-event rules (using a tagged side input or in-line predicate), then dispatches to the right per-rule transform based on `kind`.
- [ ] Tests: ruleset with one of each kind, single-stream input, assert each rule sees the right subset.
- [ ] Commit.

### Task 13: End-to-end pipeline + DirectRunner test

**Files:**
- Create: `dataflow/pipelines/__init__.py`
- Create: `dataflow/pipelines/correlation_pipeline.py`
- Create: `dataflow/tests/sigma_beam/test_e2e_direct.py`

- [ ] `correlation_pipeline.run(argv)`: Pub/Sub source → JSON parse (DLQ on fail) → SingleEventDetect (alerts + DLQ) → CorrelationDetect (alerts + DLQ) → WriteToPubSub(alerts) + WriteToPubSub(dlq).
- [ ] Pipeline options: `--input_subscription`, `--alerts_topic`, `--dlq_topic`, `--rules_uri`.
- [ ] DirectRunner test: in-memory source of 10 events, one matching a single-event rule, three matching event_count threshold, verify expected alerts in the alerts PCollection (use `TestStream` for event-time).
- [ ] Commit.

### Task 14: Rust integration — rule staging + upload

**Files:**
- Modify: `src/lib/sigma.rs`
- Modify: `src/lib/gcs.rs` (or new module)
- Modify: `src/lib/resources.rs`
- Modify: `src/commands/deploy.rs`
- Modify: `src/commands/destroy.rs`

- [ ] After `pysigma` compile step, copy resolved rule YAMLs to `<config_dir>/.beaver/rules/`.
- [ ] New deploy step: `gsutil rsync` (or storage API) `<config_dir>/.beaver/rules/` → `gs://<bucket>/rules/`.
- [ ] Resources: track `rules_gcs_prefix`.
- [ ] Destroy: `gsutil rm -r gs://<bucket>/rules/` before bucket deletion.
- [ ] Tests: `#[ignore]` integration test that runs the upload step against a real bucket.
- [ ] Commit.

### Task 15: Rust integration — alerts + DLQ topics & BQ table

**Files:**
- Modify: `src/lib/pubsub.rs`
- Modify: `src/lib/bq.rs`
- Modify: `src/lib/resources.rs`
- Modify: `src/commands/deploy.rs`
- Modify: `src/commands/destroy.rs`

- [ ] Create `beaver-alerts` topic + `beaver-alerts-to-bq` subscription.
- [ ] Create BQ `alerts` table: `rule_id STRING, rule_title STRING, severity STRING, fired_at TIMESTAMP, window_start TIMESTAMP, window_end TIMESTAMP, correlation_key STRING, matched_events JSON`. Partition by `_PARTITIONTIME`, 30d expiration.
- [ ] Create `beaver-dlq` topic (no BQ; just for ops inspection).
- [ ] Resources tracking + destroy ordering.
- [ ] Commit.

### Task 16: Rust integration — launch new pipeline

**Files:**
- Modify: `src/lib/dataflow.rs`
- Modify: `src/commands/deploy.rs`

- [ ] Switch template upload + launch to `dataflow/pipelines/correlation_pipeline.py`.
- [ ] Pass new args (`--alerts_topic`, `--dlq_topic`, `--rules_uri`) to `gcloud dataflow jobs run`.
- [ ] Leave `detections_template.py` in tree for now (deprecate later) — pipeline name is the only switch.
- [ ] Commit.

### Task 17: Dashboard tiles

**Files:**
- Modify: `src/lib/dashboard.rs`

- [ ] Tile: alerts/min (custom counter `sigma_beam.matches`).
- [ ] Tile: per-rule top-10 by match count (PromQL-style aggregation on the counter label).
- [ ] Tile: DLQ depth (Pub/Sub `num_undelivered_messages`).
- [ ] Tile: pipeline element latency (Dataflow system metric).
- [ ] Commit.

### Task 18: Real-GCP smoke test

- [ ] Deploy to `beaver-496418`.
- [ ] Publish 5 synthetic failed-login events in 30s to `beaver-test-input`.
- [ ] Verify single alert lands in `alerts` BQ table within 90s.
- [ ] Publish 1 malformed message; verify DLQ topic receives it.
- [ ] Destroy.
- [ ] Commit (only docs/changelog updates from any findings).

### Task 19: Docs

**Files:**
- Modify: `dataflow/sigma_beam/PLAN.md` (mark complete)
- Modify: `README.md` (Detection rules section)
- Create: `docs/sigma-beam.md` (concise feature writeup, ≤ 80 lines)

- [ ] Document: supported rule shapes, unsupported modifiers, correlation semantics, rule annotations (`beaver.allowed_lateness_seconds`, `beaver.allow_high_cardinality`).
- [ ] Commit.

---

## Out of scope (explicitly deferred)

- **In-flight rule reload.** v2 only.
- **Cross-correlation** (correlation of correlations). pySigma supports it; we don't.
- **Aggregation functions** other than count/distinct-count (avg, sum, percentiles). Rare in Sigma; add when needed.
- **Replacing scheduled-query detections on cold tier.** Beam is hot-path only; long-horizon (>1 day) correlations stay as scheduled SQL against `events_all`.
- **Backfill / replay.** Streaming-only; for replay, publish historical events back to input topic.

## Risks

- **State growth on temporal rules with high-cardinality keys.** Mitigated by static linter + hard TTL cap, but not eliminated.
- **Event-time ordering on temporal_ordered.** Late events break ordering; we buffer-and-sort per window, which has memory cost. Document the trade-off; cap window at 1 hour.
- **pySigma API stability.** Pin `pysigma~=0.11`. Watch correlation API for breaking changes.
- **Dataflow worker startup time on rule load.** Loading 1000 rules from GCS at startup adds seconds. Acceptable; if it grows past 30s, cache rules in container image at build time.

## Self-review checklist (run before kickoff)

- [ ] Every spec requirement mapped to a task? (single-event, all 4 correlation kinds, DLQ, metrics, rule upload, alerts sink, dashboard, smoke test → yes.)
- [ ] No placeholders / "TBD"s in any task?
- [ ] Types/names consistent across tasks (e.g., `CompiledRule`, `Alert`, `Ruleset`)?
- [ ] Each task ends with a commit?
- [ ] Open design choices listed and decidable before Task 1?
