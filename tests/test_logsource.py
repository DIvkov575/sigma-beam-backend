from pathlib import Path

from sigma_beam.loader import load_from_dir
from sigma_beam.logsource import dataset_field_filter, null_filter, product_field_filter

FIX = Path(__file__).parent / "fixtures" / "corpus_smoke"


def test_null_filter_lets_everything_through():
    rs = load_from_dir(FIX, logsource_filter=null_filter)
    aws_rule = next(r for r in rs.single_event if "Root" in r.title)
    # A Windows event still triggers the AWS rule with null filter, as long
    # as the detection matches. Detection requires userIdentity.type=Root.
    win_event = {"userIdentity": {"type": "Root"}, "eventName": "Other",
                 "product": "windows"}
    assert aws_rule.predicate(win_event)


def test_product_field_filter_blocks_wrong_product():
    rs = load_from_dir(FIX, logsource_filter=product_field_filter("product"))
    aws_rule = next(r for r in rs.single_event if "Root" in r.title)
    win_event = {"userIdentity": {"type": "Root"}, "eventName": "Other",
                 "product": "windows"}
    assert not aws_rule.predicate(win_event)
    aws_event = {"userIdentity": {"type": "Root"}, "eventName": "Other",
                 "product": "aws"}
    assert aws_rule.predicate(aws_event)


def test_dataset_field_filter():
    rs = load_from_dir(FIX, logsource_filter=dataset_field_filter("data_stream.dataset"))
    win_logon = next(r for r in rs.single_event if "Failed" in r.title)
    # Right dataset
    assert win_logon.predicate({"EventID": 4625, "data_stream": {"dataset": "windows.security"}})
    # Wrong dataset
    assert not win_logon.predicate({"EventID": 4625, "data_stream": {"dataset": "aws.cloudtrail"}})
    # Missing dataset
    assert not win_logon.predicate({"EventID": 4625})


def test_logsource_with_no_product_passes_through():
    # `network_cidr.yml` only has `category: firewall`; product-based filter
    # should pass it through (no opinion).
    rs = load_from_dir(FIX, logsource_filter=product_field_filter())
    firewall = next(r for r in rs.single_event if "SSH" in r.title)
    assert firewall.predicate({"dst_port": 22, "src_ip": "10.1.2.3"})
