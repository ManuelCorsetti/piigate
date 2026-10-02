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
        check_re2(p)


@pytest.mark.parametrize("tag", SPECS)
def test_re2_engine_agrees_with_python(tag):
    re2 = pytest.importorskip("re2")
    for src, pat in zip(SPECS[tag]["patterns"], DETS[tag].patterns, strict=True):
        r = re2.compile(src, re2.Options())
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
