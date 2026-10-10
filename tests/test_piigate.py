import pandas as pd
import pytest

from piigate import PIIFoundError, mask_shape, register_detector, scan_dataframe
from piigate import detectors as det_mod
from piigate import validators as v

RAW = {
    "EMAIL": "jane.doe@example.com",
    "PHONE": "+44 7911 123456",
    "NI_NUMBER": "AB 12 34 56 C",
    "POSTCODE": "SW1A 1AA",
    "CARD_NUMBER": "4111 1111 1111 1111",
    "IBAN": "GB82 WEST 1234 5698 7654 32",
    "SORT_CODE": "12-34-56",
    "IP_ADDRESS": "192.168.1.10",
}


def test_mask_shape():
    assert mask_shape("+44 7911 123456") == "+DD DDDD DDDDDD"
    assert mask_shape("a@b.c") == "L@L.L"
    assert mask_shape("x" * 100).endswith("…")


@pytest.mark.parametrize("tag,value", RAW.items())
def test_each_tag_detected_in_free_text(tag, value):
    df = pd.DataFrame({"notes": [f"please contact {value} asap", "nothing here"]})
    res = scan_dataframe(df, ["notes"])
    assert not res.ok
    assert tag in res.failed_columns["notes"].tags
    assert res.failed_columns["notes"].match_rate == 0.5


def test_clean_column_passes():
    df = pd.DataFrame({"notes": ["hello", "order 12345 shipped", None]})
    res = scan_dataframe(df, ["notes"])
    assert res.ok and res.passed_columns == ["notes"]


def test_name_heuristic_flags_column_without_value_match():
    df = pd.DataFrame({"first_name": ["Alice", "Bob"], "file_name": ["a.csv", "b.csv"]})
    res = scan_dataframe(df, ["first_name", "file_name"])
    assert list(res.failed_columns) == ["first_name"]
    assert res.failed_columns["first_name"].name_hint_tags == ("NAME",)
    off = scan_dataframe(df, ["first_name"], name_heuristics=False)
    assert off.ok


def test_validators_cut_false_positives():
    df = pd.DataFrame({"x": ["4111 1111 1111 1112", "GB00 WEST 1234 5698 7654 32", "DQ123456A"]})
    assert scan_dataframe(df, ["x"]).ok
    assert v.luhn("4111111111111111") and not v.luhn("4111111111111112")
    assert v.iban("GB82WEST12345698765432") and not v.iban("GB83WEST12345698765432")
    assert v.ni_number("AB123456C") and not v.ni_number("BG123456C")
    assert not v.sort_code("00-00-00")
    assert v.uk_phone("07911 123456") and not v.uk_phone("01234")


def test_threshold_is_per_tag_and_strict_by_default():
    df = pd.DataFrame({"n": [RAW["EMAIL"], "a@b.co", "clean"]})
    assert not scan_dataframe(df, ["n"]).ok
    assert scan_dataframe(df, ["n"], thresholds={"EMAIL": 2}).ok
    assert not scan_dataframe(df, ["n"], thresholds={"EMAIL": 1}).ok


def test_full_scan_default_sampling_opt_in():
    df = pd.DataFrame({"n": ["clean"] * 999 + [RAW["EMAIL"]]})
    full = scan_dataframe(df, ["n"])
    assert not full.ok and not full.sampled and full.rows_scanned == 1000
    s = scan_dataframe(df, ["n"], sample=10, random_state=0)
    assert s.sampled and s.rows_scanned == 10


def test_missing_column_raises():
    with pytest.raises(KeyError):
        scan_dataframe(pd.DataFrame({"a": [1]}), ["b"])


def test_custom_detector_explicit_and_registered():
    import re

    from piigate import Detector

    d = Detector("EMP_ID", (re.compile(r"EMP\d{6}"),))
    df = pd.DataFrame({"n": ["EMP123456"]})
    assert scan_dataframe(df, ["n"], detectors=[d]).failed_columns["n"].tags == ("EMP_ID",)
    try:
        register_detector(
            "CASE_REF", r"CASE-\d{4}", validator=lambda s: True, column_names=["caseref"]
        )
        assert (
            "CASE_REF"
            in scan_dataframe(pd.DataFrame({"n": ["CASE-1234"]}), ["n"]).failed_columns["n"].tags
        )
        assert (
            "CASE_REF"
            in scan_dataframe(pd.DataFrame({"case_ref": ["x"]}), ["case_ref"])
            .failed_columns["case_ref"]
            .tags
        )
    finally:
        det_mod._custom.clear()


def test_numeric_columns_scanned():
    df = pd.DataFrame({"card": [4111111111111111, 5]})
    assert "CARD_NUMBER" in scan_dataframe(df, ["card"]).failed_columns["card"].tags


def test_shapes_aggregated_top_n():
    df = pd.DataFrame({"n": [RAW["PHONE"]] * 3 + ["07911 123456"]})
    f = scan_dataframe(df, ["n"], top_n=1).failed_columns["n"]
    assert f.masked_shapes == (("+DD DDDD DDDDDD", 3),)


def test_no_raw_values_in_result_or_exception():
    df = pd.DataFrame(
        {
            "email": [RAW["EMAIL"]],
            "notes": [f"call {RAW['PHONE']} ref {RAW['CARD_NUMBER']}"],
            "name": ["Zebediah"],
        }
    )
    with pytest.raises(PIIFoundError) as ei:
        scan_dataframe(df, ["email", "notes", "name"], raise_on_fail=True)
    res = ei.value.result
    blob = repr(res) + str(ei.value) + repr(ei.value) + repr(res.failed_columns)
    for raw in [*RAW.values(), "Zebediah", "jane.doe", "7911", "4111"]:
        assert raw not in blob
        assert raw.replace(" ", "") not in blob
