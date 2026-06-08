"""Beaver SIEM streaming pipeline: Pub/Sub → SigmaBeam → Pub/Sub alerts + DLQ.

Reads JSON events from an input Pub/Sub subscription, runs them through every
single-event rule and every correlation rule in the ruleset (loaded once at
worker startup from --rules_uri, which can be either gs://... or a local
path), and publishes resulting `Alert` JSON to --alerts_topic. Parse errors
and per-rule evaluation errors are JSON-encoded and published to --dlq_topic.
"""

from __future__ import annotations

import json
import logging

import apache_beam as beam
from apache_beam.options.pipeline_options import GoogleCloudOptions, PipelineOptions
from apache_beam.transforms.window import GlobalWindows

from sigma_beam.correlation.fanout import CorrelationFanout
from sigma_beam.dlq import format_dlq
from sigma_beam.loader import load_from_dir, load_from_gcs
from sigma_beam.ruleset import Ruleset
from sigma_beam.single_event import DLQ, MAIN, SingleEventDetect

log = logging.getLogger(__name__)


class SigmaBeamOptions(PipelineOptions):
    @classmethod
    def _add_argparse_args(cls, parser):
        # Not required=True at argparse level: SigmaBeamOptions is auto-discovered
        # by any PipelineOptions() instantiation. run() enforces required-ness.
        parser.add_argument("--input_subscription", default=None,
                            help="Pub/Sub subscription id (project from --project)")
        parser.add_argument("--alerts_topic", default=None,
                            help="Pub/Sub topic id for alerts")
        parser.add_argument("--dlq_topic", default=None,
                            help="Pub/Sub topic id for dead-letter")
        parser.add_argument("--rules_uri", default=None,
                            help="gs://bucket/prefix or local dir holding Sigma YAMLs")


class _ParseJson(beam.DoFn):
    def process(self, msg):
        if hasattr(msg, "data"):
            raw = msg.data.decode("utf-8", errors="replace")
        elif isinstance(msg, bytes):
            raw = msg.decode("utf-8", errors="replace")
        else:
            raw = msg
        try:
            yield json.loads(raw)
        except (json.JSONDecodeError, TypeError) as exc:
            yield beam.pvalue.TaggedOutput(
                "dlq", format_dlq("non-JSON message", raw, exc)
            )


def build_pipeline(
    p: beam.Pipeline,
    ruleset: Ruleset,
    source: beam.PTransform,
    alerts_sink: beam.PTransform,
    dlq_sink: beam.PTransform,
    *,
    pass_alert_objects: bool = False,
) -> None:
    """Wire the detection graph onto `p`.

    Defaults to passing JSON-encoded `bytes` to `alerts_sink` for maximum
    sink compatibility (e.g., `WriteToText` in tests). Production code that
    wants Pub/Sub-attribute tagging should set `pass_alert_objects=True`
    and use `AlertsToPubSub` as the sink — it converts `Alert` → `PubsubMessage`
    with `severity` / `rule_id` attributes for downstream filtering.
    """
    msgs = p | "Read" >> source
    parsed = msgs | "ParseJSON" >> beam.ParDo(_ParseJson()).with_outputs("dlq", main="events")

    events = parsed.events
    parse_dlq = parsed.dlq

    se = events | "SingleEvent" >> SingleEventDetect(ruleset.single_event)
    corr = events | "Correlation" >> CorrelationFanout(ruleset)

    # Correlation outputs live in FixedWindows; realign both branches to the
    # global window before flattening so Beam can union them.
    se_g = se[MAIN] | "SeGlobal" >> beam.WindowInto(GlobalWindows())
    corr_g = corr | "CorrGlobal" >> beam.WindowInto(GlobalWindows())
    alerts = [se_g, corr_g] | "FlattenAlerts" >> beam.Flatten()

    if pass_alert_objects:
        alerts | "PublishAlerts" >> alerts_sink
    else:
        alerts | "AlertToBytes" >> beam.Map(lambda a: a.to_bytes()) \
               | "WriteAlerts" >> alerts_sink

    all_dlq = [parse_dlq, se[DLQ]] | "FlattenDLQ" >> beam.Flatten()
    all_dlq | "WriteDLQ" >> dlq_sink


class _AlertToPubsubMessage(beam.DoFn):
    """Convert an Alert into a PubsubMessage with severity (+rule_id) attributes
    so subscribers can filter natively (`attributes.severity = "critical"`)."""

    def process(self, alert):
        from apache_beam.io.gcp.pubsub import PubsubMessage
        # to_bq_bytes (not to_bytes): the alerts topic feeds a BigQuery
        # subscription whose JSON columns require nested fields as JSON strings.
        yield PubsubMessage(
            data=alert.to_bq_bytes(),
            attributes={"severity": alert.severity, "rule_id": alert.rule_id},
        )


class AlertsToPubSub(beam.PTransform):
    """Tag → publish. Use as `alerts_sink` in `build_pipeline` for Pub/Sub."""

    def __init__(self, topic: str) -> None:
        super().__init__()
        self._topic = topic

    def expand(self, alerts):
        return (
            alerts
            | "TagAttrs" >> beam.ParDo(_AlertToPubsubMessage())
            | "PublishAlerts" >> beam.io.WriteToPubSub(
                topic=self._topic, with_attributes=True,
            )
        )


def _topic_path(project: str, topic_id: str) -> str:
    return f"projects/{project}/topics/{topic_id}"


def run(argv=None) -> None:
    options = PipelineOptions(argv, streaming=True)
    opts = options.view_as(SigmaBeamOptions)
    gc = options.view_as(GoogleCloudOptions)

    missing = [
        n for n in ("input_subscription", "alerts_topic", "dlq_topic", "rules_uri")
        if getattr(opts, n) is None
    ]
    if missing:
        raise SystemExit(
            f"sigma_beam.correlation_pipeline: missing required --{', --'.join(missing)}"
        )

    log.info("loading rules from %s", opts.rules_uri)
    if opts.rules_uri.startswith("gs://"):
        rs = load_from_gcs(opts.rules_uri)
    else:
        rs = load_from_dir(opts.rules_uri)
    log.info("ruleset: %d single-event, %d correlation",
             len(rs.single_event), len(rs.correlation))

    sub = f"projects/{gc.project}/subscriptions/{opts.input_subscription}"
    alerts_topic = _topic_path(gc.project, opts.alerts_topic)
    dlq_topic = _topic_path(gc.project, opts.dlq_topic)

    with beam.Pipeline(options=options) as p:
        build_pipeline(
            p, rs,
            source=beam.io.ReadFromPubSub(subscription=sub, with_attributes=True),
            alerts_sink=AlertsToPubSub(alerts_topic),
            dlq_sink=beam.io.WriteToPubSub(topic=dlq_topic),
            pass_alert_objects=True,
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()
