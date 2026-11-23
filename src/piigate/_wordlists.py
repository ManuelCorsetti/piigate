"""Small embedded word lists for dictionary-style detectors. Kept deliberately short.

First names exclude ones that are also common English words (Will, Mark, Grace, May, Rose...)
to keep free-text false positives down; NAME in free text is still best-effort.
"""

from __future__ import annotations

FIRST_NAMES: tuple[str, ...] = tuple(
    """
    Oliver George Harry Noah Jacob Charlie Thomas Oscar William James Henry Leo Alfie Joshua
    Freddie Archie Ethan Isaac Alexander Joseph Edward Samuel Daniel Arthur Lucas Mohammed
    Muhammad Logan Theo Harrison Benjamin Dylan Sebastian Adam Riley Elliot Toby Jake Luke Ryan
    Liam Callum Connor Kieran Nathan Matthew Andrew David Paul Stephen Steven Michael Christopher
    Richard Robert Peter Anthony Simon Ian Gary Kevin Martin Neil Graham Stuart Colin Keith Derek
    Trevor Nigel Barry Gareth Craig Darren Jason Wayne Dean Shaun Jonathan Timothy Philip Alan
    Brian John Ahmed Hassan Omar Sanjay Arjun Rahul Hamza Yusuf Ibrahim Declan Ciaran Owen Rhys
    Olivia Amelia Isla Ava Mia Isabella Sophia Sophie Lily Emily Ella Evie Freya Charlotte Poppy
    Isabelle Jessica Chloe Harper Ellie Phoebe Millie Florence Matilda Scarlett Sienna Layla
    Zara Hannah Lucy Holly Megan Amy Rebecca Rachel Laura Sarah Emma Gemma Kirsty Claire Nicola
    Lisa Michelle Helen Karen Julie Susan Elizabeth Margaret Patricia Jennifer Catherine Katherine
    Victoria Natalie Samantha Danielle Lauren Jade Abigail Eleanor Alice Fatima Aisha Priya Mary
    Linda Deborah Joanne Louise Jane Fiona Alison Angela Wendy Tracey Andrea Kathryn Siobhan
    Niamh Aoife Caitlin Bethany Shannon Chantelle Leanne Kayleigh Rhiannon Ffion Sian Zainab
    Maryam Ayesha Nadia
    """.split()
)

HEALTH_TERMS: tuple[str, ...] = (  # literals, lowercase
    "diabetes", "diabetic", "cancer", "tumour", "tumor", "leukaemia", "leukemia", "lymphoma",
    "melanoma", "hiv", "hepatitis", "tuberculosis", "asthma", "asthmatic", "epilepsy",
    "epileptic", "dementia", "alzheimer's", "alzheimers", "parkinson's", "parkinsons",
    "multiple sclerosis",
    "cystic fibrosis", "motor neurone disease", "schizophrenia", "schizophrenic",
    "bipolar disorder", "depression", "depressive", "anxiety disorder", "ptsd",
    "post-traumatic stress", "autism", "autistic", "adhd", "dyslexia", "dyslexic", "anorexia",
    "bulimia", "eating disorder", "self-harm", "self harm", "suicidal", "overdose", "chemotherapy",
    "radiotherapy", "dialysis", "insulin", "pregnant", "pregnancy", "miscarriage", "abortion",
    "ivf", "heart attack", "myocardial infarction", "hypertension", "copd", "chlamydia",
    "gonorrhoea", "gonorrhea", "syphilis", "herpes", "sexually transmitted", "mental health",
    "mental illness", "disabled", "disability", "wheelchair user", "amputee", "sertraline",
    "fluoxetine", "citalopram", "metformin", "methadone", "antidepressant", "antidepressants",
)

ETHNIC_PHRASES: tuple[str, ...] = (
    r"white (?:british|irish|english|scottish|welsh|other)",
    r"(?:gypsy or )?irish traveller",
    r"black (?:british|caribbean|african|other)",
    r"mixed (?:race|ethnicity|heritage)",
    r"(?:mixed[: ]+)?white and (?:black caribbean|black african|asian)",
    r"asian (?:british|other)",
    r"british (?:asian|indian|pakistani|bangladeshi|chinese|african|caribbean)",
)

ISO_COUNTRIES = frozenset(
    """
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR
    BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ
    EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW
    GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY
    KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV
    MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY
    QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG
    TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA
    ZM ZW
    """.split()
)


def trie_regex(words: tuple[str, ...]) -> str:
    """Literal words -> one regex sharing prefixes. Far faster than a flat ``a|b|c`` in ``re``."""
    import re

    trie: dict = {}
    for w in words:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node: dict) -> str:
        end = "" in node
        alts = [re.escape(ch) + build(child) for ch, child in sorted(node.items()) if ch]
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 else "(?:" + "|".join(alts) + ")"
        if end:
            return f"(?:{body})?"
        return body

    return build(trie)
