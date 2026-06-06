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
from typing import Any

import apache_beam as beam
from apache_beam.options.pipeline_options import GoogleCloudOptions, PipelineOptions
from apache_beam.transforms.window import GlobalWindows

from sigma_beam.correlation.fanout import CorrelationFanout
from sigma_beam.dlq import format_dlq
from sigma_beam.loader import load_from_dir, load_from_gcs
from sigma_beam.single_event import DLQ, MAIN, SingleEventDetect

log = logging.getLogger(__name__)


class SigmaBeamOptions(PipelineOptions):
    @classmethod
    def _add_argparse_args(cls, parser):
        parser.add_argument("--input_subscription", required=True,
                            help="Pub/Sub subscription id (project from --project)")
        parser.add_argument("--alerts_topic", required=True,
                            help="Pub/Sub topic id for alerts")
        parser.add_argument("--dlq_topic", required=True,
                            help="Pub/Sub topic id for dead-letter")
        parser.add_argument("--rules_uri", required=True,
                            help="gs://bucket/prefix or local dir holding Sigma YAMLs")


class _ParseJson(beam.DoFn):
    def process(self, msg):
        raw = msg.data.decode("utf-8", errors="replace") if hasattr(msg, "data") else msg
        try:
            yield json.loads(raw)
        except json.JSONDecodeError as exc:
            yield beam.pvalue.TaggedOutput(
                "dlq", format_dlq("non-JSON message", raw, exc)
            )


def _topic_path(project: str, topic_id: str) -> str:
    return f"projects/{project}/topics/{topic_id}"


def run(argv=None) -> None:
    options = PipelineOptions(argv, streaming=True)
    opts = options.view_as(SigmaBeamOptions)
    gc = options.view_as(GoogleCloudOptions)

    log.info("loading rules from %s", opts.rules_uri)
    if opts.rules_uri.startswith("gs://"):
        rs = load_from_gcs(opts.rules_uri)
    else:
        rs = load_from_dir(opts.rules_uri)
    log.info(
        "ruleset: %d single-event, %d correlation, %d nested",
        len(rs.single_event), len(rs.correlation), len(rs.nested_correlation),
    )

    sub = f"projects/{gc.project}/subscriptions/{opts.input_subscription}"
    alerts_topic = _topic_path(gc.project, opts.alerts_topic)
    dlq_topic = _topic_path(gc.project, opts.dlq_topic)

    with beam.Pipeline(options=options) as p:
        msgs = (
            p
            | "Read" >> beam.io.ReadFromPubSub(subscription=sub, with_attributes=True)
        )
        parsed = (
            msgs | "ParseJSON" >> beam.ParDo(_ParseJson()).with_outputs("dlq", main="events")
        )

        events = parsed.events
        parse_dlq = parsed.dlq

        # Single-event detection
        se = events | "SingleEvent" >> SingleEventDetect(rs.single_event)

        # Correlation
        corr = events | "Correlation" >> CorrelationFanout(rs)

        # Correlation outputs are FixedWindowed; realign both branches to the
        # global window before flattening so Beam can union them.
        se_g = se[MAIN] | "SeGlobal" >> beam.WindowInto(GlobalWindows())
        corr_g = corr | "CorrGlobal" >> beam.WindowInto(GlobalWindows())
        alerts = (
            [se_g, corr_g]
            | "FlattenAlerts" >> beam.Flatten()
            | "AlertToBytes" >> beam.Map(lambda a: a.to_bytes())
        )
        alerts | "PublishAlerts" >> beam.io.WriteToPubSub(topic=alerts_topic)

        # Merge DLQ from parse + single-event errors → Pub/Sub
        all_dlq = ([parse_dlq, se[DLQ]] | "FlattenDLQ" >> beam.Flatten())
        all_dlq | "PublishDLQ" >> beam.io.WriteToPubSub(topic=dlq_topic)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()
