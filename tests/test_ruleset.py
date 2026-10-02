import json
from importlib import resources

import pandas as pd
import pytest

from piigate import load_ruleset, scan_dataframe
from piigate.detectors import default_detectors, normalise_name
from piigate.ruleset import check_re2

DOC = json.loads(resources.files("piigate").joinpath("rules", "uk_gdpr.json").read_text("utf-8"))
SPECS = {d["tag"]: d for d in DOC["detectors"]}
DETS = {d.tag: d for d in load_ruleset("uk_gdpr")}


def _chain(gate):
    return [gate] if isinstance(gate, str) else list(gate or ())


def test_bundled_ruleset_matches_defaults():
    assert [d.tag for d in default_detectors()] == [d["tag"] for d in DOC["detectors"]]


@pytest.mark.parametrize("tag", SPECS)
def test_example_vectors(tag):
    det = DETS[tag]
    for text in SPECS[tag]["examples"]["match"]:
        assert list(det.matches(text)), f"{tag} should match {text!r}"
    for text in SPECS[tag]["examples"]["no_match"]:
        assert not list(det.matches(text)), f"{tag} should not match {text!r}"


@pytest.mark.parametrize("tag", SPECS)
def test_column_name_vectors(tag):
    det = DETS[tag]
    cn = SPECS[tag]["column_names"]
    for name in cn["hit"]:
        assert det.name_hint and det.name_hint(normalise_name(name)), name
    for name in cn["miss"]:
        assert not (det.name_hint and det.name_hint(normalise_name(name))), name


@pytest.mark.parametrize("tag", SPECS)
def test_patterns_are_re2_compatible(tag):
    for p in SPECS[tag]["patterns"]:
        check_re2(p["regex"])
        for g in _chain(p.get("gate")):
            check_re2(g)


@pytest.mark.parametrize("tag", SPECS)
def test_re2_engine_agrees_with_python(tag):
    re2 = pytest.importorskip("re2")
    for spec, pat in zip(SPECS[tag]["patterns"], DETS[tag].patterns, strict=True):
        src = spec["regex"]
        r = re2.compile(src)
        for g in _chain(spec.get("gate")):
            re2.compile(g)
        corpus = SPECS[tag]["examples"]["match"] + SPECS[tag]["examples"]["no_match"]
        for text in corpus:
            py = pat.search(text)
            rm = r.search(text)
            assert (py is None) == (rm is None), (tag, src, text)
            if py:
                assert py.group(1) == rm.group(1), (tag, src, text)


@pytest.mark.parametrize(
    "bad",
    [r"(?<=a)b", r"(?<!a)b", r"a(?=b)", r"a(?!b)", r"(a)\1", r"(?>a)", r"a++", r"(a)\Z"],
)
def test_check_re2_rejects(bad):
    with pytest.raises(ValueError):
        check_re2(bad)


def test_check_re2_ignores_escapes_and_classes():
    check_re2(r"(?:^|[^\w.+-])([\w.+-]+@x\.y)")
    check_re2(r"[*+]+(a)\(\?=")


def _doc(**over):
    d = {"tag": "X", "patterns": [r"(?:^|\D)(\d{3})"], "validator": None}
    d.update(over)
    return {"version": 1, "detectors": [d]}


def test_loader_validation():
    assert load_ruleset(_doc())[0].tag == "X"
    with pytest.raises(ValueError, match="validator"):
        load_ruleset(_doc(validator="nope"))
    with pytest.raises(ValueError, match="one capture group"):
        load_ruleset(_doc(patterns=[r"\d{3}"]))
    with pytest.raises(ValueError, match="one capture group"):
        load_ruleset(_doc(patterns=[r"(\d)(\d)"]))
    with pytest.raises(ValueError, match="RE2"):
        load_ruleset(_doc(patterns=[r"(?<!a)(\d{3})"]))
    with pytest.raises(ValueError, match="version"):
        load_ruleset({"version": 2, "detectors": []})


def test_load_from_file_and_scan(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text(
        json.dumps(
            _doc(tag="EMP", patterns=[r"(?:^|\W)(EMP\d{4})"], name_hint={"fragments": ["empid"]})
        )
    )
    dets = load_ruleset(p)
    df = pd.DataFrame({"n": ["id EMP1234"], "empid": ["x"], "ok": ["fine"]})
    res = scan_dataframe(df, ["n", "empid", "ok"], detectors=dets)
    assert set(res.failed_columns) == {"n", "empid"} and res.passed_columns == ["ok"]


def test_adjacent_matches_not_lost_to_boundaries():
    def n(text, tag):
        return len(list(DETS[tag].matches(text)))

    assert n("a@b.co,c@d.co;e@f.co", "EMAIL") == 3
    assert n("1.2.3.4,5.6.7.8 9.9.9.9", "IP_ADDRESS") == 3
    assert n("12-34-56 65-43-21", "SORT_CODE") == 2


def test_valid_match_overlapping_rejected_candidate_is_found():
    text = "4111 1111 1111 1112 4111 1111 1111 1111"
    assert list(DETS["CARD_NUMBER"].matches(text)) == ["4111 1111 1111 1111"]


def test_gates_are_necessary_conditions():
    """A gate may only skip a row if no match is possible: pattern match => gate match."""
    import random

    rng = random.Random(0)
    alphabet = "0123456789019abcdefABCGBWESTNIXZ@:.-+() \t"
    corpus = [t for d in SPECS.values() for t in d["examples"]["match"] + d["examples"]["no_match"]]
    corpus += ["".join(rng.choices(alphabet, k=rng.randint(1, 40))) for _ in range(40_000)]
    for det in DETS.values():
        for i, pat in enumerate(det.patterns):
            for text in corpus:
                if pat.search(text):
                    for gate in det.gate_for(i):
                        assert gate.search(text), (det.tag, i, gate.pattern, text)


def test_gates_do_not_change_results():
    corpus = ["x", "", "plain words", "07911 123456", "a@b.co", "ip:10.0.0.1", "::1 12:30:45"]
    for tag in SPECS:
        corpus += SPECS[tag]["examples"]["match"] + SPECS[tag]["examples"]["no_match"]
    df = pd.DataFrame({"c": corpus * 3})
    gated = scan_dataframe(df, ["c"])
    ungated = scan_dataframe(
        df,
        ["c"],
        detectors=[
            type(d)(d.tag, d.patterns, d.validator, None, d.group) for d in default_detectors()
        ],
    )
    assert gated == ungated


def test_dedup_weights_counts_by_row():
    df = pd.DataFrame({"c": ["a@b.co"] * 7 + ["clean"] * 3 + [None]})
    f = scan_dataframe(df, ["c"]).failed_columns["c"]
    assert f.match_count == 7 and f.match_rate == 0.7 and f.masked_shapes == (("L@L.LL", 7),)


def _mixed_df():
    corpus = ["x", "", "plain words", "07911 123456", "a@b.co", "ip:10.0.0.1", "::1 12:30:45"]
    for tag in SPECS:
        corpus += SPECS[tag]["examples"]["match"] + SPECS[tag]["examples"]["no_match"]
    corpus += ["café 07911 123456 ñ", "x" * 500, None, 42, 4111111111111111]
    return pd.DataFrame({"c": corpus * 2, "first_name": ["a"] * (len(corpus) * 2)})


def test_engines_give_identical_results():
    pytest.importorskip("re2")
    df = _mixed_df()
    cols = ["c", "first_name"]
    assert scan_dataframe(df, cols, engine="re2") == scan_dataframe(df, cols, engine="python")


def test_re2_engine_still_runs_non_portable_custom_detectors():
    pytest.importorskip("re2")
    import re

    from piigate import Detector

    custom = Detector("REF", (re.compile(r"(?<=REF-)\d{4}"),))  # lookbehind: Python-only
    df = pd.DataFrame({"c": ["see REF-1234", "a@b.co", "clean"]})
    res = scan_dataframe(df, ["c"], detectors=[*default_detectors(), custom], engine="re2")
    assert set(res.failed_columns["c"].tags) == {"REF", "EMAIL"}


def test_re2_engine_requires_package(monkeypatch):
    import piigate.scanner as sc

    monkeypatch.setattr(sc, "_have_re2", lambda: False)
    with pytest.raises(ImportError, match="piigate\\[fast\\]"):
        scan_dataframe(pd.DataFrame({"c": ["x"]}), ["c"], engine="re2")
    assert scan_dataframe(pd.DataFrame({"c": ["a@b.co"]}), ["c"]).failed_columns  # auto: python
