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

    d = Detector("EMP_ID", re.compile(r"EMP\d{6}"))
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


# --- Extended detector coverage -------------------------------------------------------------

RAW_EXTENDED = {
    "NHS_NUMBER": "NHS 943 476 5919",
    "CHI_NUMBER": "CHI 0101011237",
    "PASSPORT_NUMBER": "passport no. 120382978",
    "DRIVING_LICENCE": "MORGA753116SM9IJ",
    "UTR": "UTR 12345 67890",
    "PHONE": "+33 6 12 34 56 78",
    "NAME": "spoke to Sarah Thompson",
    "STREET_ADDRESS": "10 Downing Street",
    "DOB": "born 14/02/1987",
    "GENDER": None,  # column-name only
    "HEALTH": "diagnosed with diabetes",
    "ETHNIC_GROUP": "White British",
    "SWIFT_CODE": "BIC NWBKGB2L",
    "MAC_ADDRESS": "00:1A:2B:3C:4D:5E",
    "IMEI": "imei 490154203237518",
    "LOCATION_COORDINATES": "51.50340, -0.12760",
    "VIN": "1HGCM82633A004352",
    "VEHICLE_REGISTRATION": "reg AB12 CDE",
    "AWS_CREDENTIALS": "AKIAIOSFODNN7EXAMPLE",
    "GCP_API_KEY": "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
    "JSON_WEB_TOKEN": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3",
    "PRIVATE_KEY": "-----BEGIN RSA PRIVATE KEY-----",
    "AUTH_TOKEN": "Bearer abcdefghijklmnopqrstuvwxyz123456",
    "PASSWORD": "password=hunter2",
    "EMAIL": "u=jane%40example.com",
}


@pytest.mark.parametrize("tag,value", [(t, v) for t, v in RAW_EXTENDED.items() if v])
def test_extended_tags_detected_in_free_text(tag, value):
    df = pd.DataFrame({"notes": [f"note: {value} end", "nothing here"]})
    f = scan_dataframe(df, ["notes"]).failed_columns["notes"]
    assert tag in f.tags
    assert f.match_rate == 0.5


@pytest.mark.parametrize(
    "value",
    [
        "SWIFT transfer completed",
        "Dear Sir, thanks",
        "the bicycle was red",
        "Tracking 0012345678",
        "password: ********",
        "pwd=null",
        "Contact Support for help",
        "London Bridge",
        "hash 5f4dcc3b5aa765d61d8327deb882cf99",
        "uuid 123e4567-e89b-12d3-a456-426614174000",
        "Total: 1,234.56 GBP",
    ],
)
def test_extended_detectors_leave_clean_text_alone(value):
    assert scan_dataframe(pd.DataFrame({"n": [value]}), ["n"]).ok


def test_intl_phone_not_mistaken_for_sort_code():
    f = scan_dataframe(pd.DataFrame({"n": ["+33 6 12 34 56 78"]}), ["n"]).failed_columns["n"]
    assert f.tags == ("PHONE",)


def test_column_name_hints_for_new_tags():
    cols = ["gender", "ethnicity", "religion", "home_address", "ip_address", "email_address"]
    res = scan_dataframe(pd.DataFrame({c: ["x"] for c in cols}), cols)
    tags = {c: f.tags for c, f in res.failed_columns.items()}
    assert tags["gender"] == ("GENDER",)
    assert tags["ethnicity"] == ("ETHNIC_GROUP",)
    assert tags["religion"] == ("RELIGION",)
    assert tags["home_address"] == ("STREET_ADDRESS",)
    assert "STREET_ADDRESS" not in tags["ip_address"] + tags["email_address"]


def test_same_text_counted_once_per_tag():
    # "Sarah Thompson" matches both the context and the first-name NAME detectors.
    f = scan_dataframe(pd.DataFrame({"n": ["spoke to Sarah Thompson"]}), ["n"]).failed_columns["n"]
    assert f.tag_counts == {"NAME": 1}
    assert f.masked_shapes == (("LLLLL LLLLLLLL", 1),)  # value group only, not the hotword


def test_new_validators():
    assert v.nhs_number("9434765919") and not v.nhs_number("9434765918")
    assert v.chi_number("0101011237") and not v.chi_number("3213011237")
    assert v.uk_driving_licence("MORGA753116SM9IJ")
    assert not v.uk_driving_licence("MORGA713116SM9IJ")  # month 13
    assert v.intl_phone("+1 415 555 0132") and not v.intl_phone("+44 7911 123456")
    assert v.vin("1HGCM82633A004352") and not v.vin("ABCDEFGHJKLMNPRST")
    assert v.swift_code("NWBKGB2L") and not v.swift_code("TRANSFER")


def test_custom_detector_value_group():
    register_detector("STAFF_ID", r"(?i:staff\s+id)\s*(?P<v>\d{6})", column_names=())
    try:
        f = scan_dataframe(pd.DataFrame({"n": ["staff id 123456", "123456"]}), ["n"])
        assert f.failed_columns["n"].masked_shapes == (("DDDDDD", 1),)
        assert f.failed_columns["n"].match_rate == 0.5
    finally:
        det_mod._custom.clear()


# --- Scan configuration -------------------------------------------------------------------


def _frame():
    return pd.DataFrame(
        {
            "email": ["a@b.co", "c@d.co", None, "e@f.co"],
            "notes": ["fine", "fine", f"call {RAW['PHONE']}", "fine"],
            "ts": pd.to_datetime(["2026-01-01", "2026-02-01", "2026-03-01", "2026-04-01"]),
        },
        index=["alice@x.com", "bob@x.com", "c", "d"],  # labels that are themselves PII
    )


def test_all_columns_by_default_and_exclude():
    res = scan_dataframe(_frame(), exclude_columns=["ts"])
    assert set(res.failed_columns) == {"email", "notes"}
    assert scan_dataframe(_frame(), exclude_columns=["email", "notes", "ts"]).ok


def test_time_window_incremental_scan():
    df = _frame()
    res = scan_dataframe(df, ["notes"], timestamp_column="ts", since="2026-03-01")
    assert not res.ok and res.rows_scanned == 2 and res.rows_total == 4
    assert scan_dataframe(df, ["notes"], timestamp_column="ts", until="2026-03-01").ok
    with pytest.raises(ValueError):
        scan_dataframe(df, ["notes"], since="2026-03-01")


def test_sample_fraction_and_head():
    df = pd.DataFrame({"n": ["clean"] * 10})
    assert scan_dataframe(df, ["n"], sample=0.3).rows_scanned == 3
    assert scan_dataframe(df, ["n"], sample=0.3, sample_method="head").sampled
    with pytest.raises(ValueError):
        scan_dataframe(df, ["n"], sample=5, sample_method="bogus")


def test_max_findings_truncates_and_guards_thresholds():
    df = pd.DataFrame({"n": [RAW["EMAIL"]] * 10})
    f = scan_dataframe(df, ["n"], max_findings=3).failed_columns["n"]
    assert f.truncated and f.match_count == 3
    with pytest.raises(ValueError):
        scan_dataframe(df, ["n"], max_findings=3, thresholds={"EMAIL": 5})


def test_fail_fast_skips_remaining_columns():
    res = scan_dataframe(_frame(), ["email", "notes", "ts"], fail_fast=True)
    assert list(res.failed_columns) == ["email"]
    assert res.skipped_columns == ["notes", "ts"]


# --- Findings -------------------------------------------------------------------------------


def test_sensitivity_and_warn_below_bar():
    df = pd.DataFrame({"ip": ["10.0.0.1"], "ni": [RAW["NI_NUMBER"]]})
    strict = scan_dataframe(df, ["ip", "ni"])
    assert set(strict.failed_columns) == {"ip", "ni"}  # default: everything fails
    res = scan_dataframe(df, ["ip", "ni"], fail_sensitivity="HIGH")
    assert list(res.failed_columns) == ["ni"] and res.failed_columns["ni"].sensitivity == "HIGH"
    assert res.warnings["ip"].tags == ("IP_ADDRESS",) and res.warnings["ip"].sensitivity == "LOW"
    assert "ip" in res.passed_columns
    with pytest.raises(ValueError):
        scan_dataframe(df, ["ip"], fail_sensitivity="CRITICAL")


def test_row_positions_are_positional_not_labels():
    res = scan_dataframe(_frame(), ["email", "notes"], include_rows=True)
    assert res.failed_columns["email"].row_positions == (0, 1, 3)  # null row 2 skipped
    assert res.failed_columns["notes"].row_positions == (2,)
    assert scan_dataframe(_frame(), ["notes"]).failed_columns["notes"].row_positions is None
    assert "alice" not in res.to_json()


def test_to_dict_and_json():
    res = scan_dataframe(_frame(), ["email", "notes"])
    d = res.to_dict()
    assert d["ok"] is False and d["failed_columns"]["email"]["tags"] == ["EMAIL"]
    assert '"ok": false' in res.to_json()


# --- Re-identification risk --------------------------------------------------------------


def _qi_frame():
    return pd.DataFrame(
        {
            "postcode": ["SW1A 1AA", "SW1A 1AA", "M1 1AE", "LS1 4AP"],
            "date_of_birth": ["1990-01-01", "1990-01-01", "1985-05-05", "1970-07-07"],
            "gender": ["F", "F", "M", "F"],
        }
    )


def test_reidentification_risk_reported_and_min_k():
    df = _qi_frame()
    res = scan_dataframe(df, fail_sensitivity="HIGH")  # QI tags only warn...
    risk = res.reidentification_risk
    assert res.ok and risk is not None  # ...and risk is report-only without min_k
    assert set(risk.columns) == {"postcode", "date_of_birth", "gender"}
    assert risk.k == 1 and risk.unique_rows == 2 and risk.unique_rate == 0.5
    with pytest.raises(PIIFoundError) as ei:
        scan_dataframe(df, fail_sensitivity="HIGH", min_k=2, raise_on_fail=True)
    assert "k=1 < 2" in str(ei.value)
    assert scan_dataframe(df.iloc[:2], fail_sensitivity="HIGH", min_k=2).ok  # k=2
    for raw in ["SW1A", "1990-01-01"]:
        assert raw not in str(ei.value) + repr(ei.value.result)


def test_single_quasi_identifier_has_no_risk_entry():
    res = scan_dataframe(_qi_frame(), ["postcode"])
    assert res.reidentification_risk is None


def test_no_raw_values_for_extended_tags():
    df = pd.DataFrame({"notes": [v for v in RAW_EXTENDED.values() if v]})
    res = scan_dataframe(df, ["notes"], include_rows=True)
    blob = repr(res) + res.to_json()
    for raw in ["9434765919", "943 476 5919", "MORGA753116SM9IJ", "Sarah", "hunter2",
                "AKIAIOSFODNN7EXAMPLE", "NWBKGB2L", "1HGCM82633A004352", "diabetes"]:
        assert raw not in blob
