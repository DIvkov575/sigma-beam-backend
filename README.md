# sigma-beam

Apache Beam runtime for [Sigma](https://sigmahq.io) detection and correlation rules. Single-event detection runs as a stateless `ParDo`; correlation rules (`event_count`, `value_count`, `temporal`, `temporal_ordered`) run as windowed combiners or stateful DoFns. Designed to run on Google Cloud Dataflow but works on any Beam runner.

## Status

- **3132 / 3132 SigmaHQ rules compile** (100%).
- 6264 Hypothesis fuzz invocations across the corpus — zero failures.
- 95+ unit + integration tests passing.

## Quick start

```bash
pip install -e .[pipelines,test]
pytest
```

Run the production pipeline on Dataflow:

```bash
python -m sigma_beam.correlation_pipeline \
    --runner DataflowRunner \
    --project my-project \
    --region us-east1 \
    --input_subscription beaver-events-sub \
    --alerts_topic beaver-alerts \
    --dlq_topic beaver-dlq \
    --rules_uri gs://my-bucket/rules/ \
    --temp_location gs://my-bucket/dataflow/temp
```

## Layout

```
src/sigma_beam/
  field_access.py        nested-dict access + MISSING sentinel
  predicates.py          primitive value predicates
  conditions.py          pySigma AST → Callable[[dict], bool]
  ruleset.py             CompiledRule / CompiledCorrelation dataclasses
  loader.py              load_from_dir / load_from_gcs
  logsource.py           pluggable logsource filter policy
  processing.py          pySigma processing-pipeline integration
  alerts.py · dlq.py · metrics.py · errors.py
  single_event.py        SingleEventDetect PTransform
  correlation/           event_count / value_count / temporal / temporal_ordered / fanout
  correlation_pipeline.py   end-to-end Pub/Sub → alerts pipeline
  coverage.py            coverage harness (compile-rate + runtime probe)
  cli_corpus.py          coverage CLI
```

See [`DESIGN.md`](DESIGN.md) for the design rationale.

## Placeholder tables

Rules using `|expand` require a placeholder table at load time:

```python
from sigma_beam.loader import load_from_dir

rs = load_from_dir("rules/", placeholders={
    "admin_users": ["alice", "bob", "root"],
    "critical_hosts": ["dc01", "dc02", "ca01"],
})
```

## Coverage harness

```bash
sigma-beam-corpus path/to/sigma/rules
# or:
python -m sigma_beam.cli_corpus path/to/sigma/rules
```

Prints compile rate, top unsupported constructs, and runtime errors against a synthetic event panel.

## Supported Sigma 2 features

| Feature | Status |
|---|---|
| AND / OR / NOT, `1 of`/`any of`/`all of` | ✅ |
| Modifiers: `endswith` / `startswith` / `contains` / `re` / `cidr` / `gte`/`gt`/`lte`/`lt` | ✅ |
| Modifiers: `cased`, `exists`, `fieldref`, `windash`, `base64`, `base64offset|contains`, `wide` | ✅ |
| Case-insensitive string equality (Sigma 2 default) | ✅ |
| Keyword search | ✅ |
| Correlation: `event_count`, `value_count`, `temporal`, `temporal_ordered` | ✅ |
| Processing pipelines (sysmon, windows) per logsource | ✅ (opt-in) |
| Logsource filtering | ✅ (opt-in, pluggable policy) |
| `|expand` placeholder substitution | ✅ (requires placeholder table) |
| Correlation: nested (correlation-of-correlations) | ✅ (one level) |
| Correlation: percentile aggregation | ✅ (beaver extension) |
| Correlation aliases | ❌ |
