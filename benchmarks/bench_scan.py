"""Scan-time benchmark: ``python benchmarks/bench_scan.py [auto|python|re2] [rows]``."""

import random
import sys
import time

import pandas as pd

from piigate import scan_dataframe

engine = sys.argv[1] if len(sys.argv) > 1 else "auto"
n = int(sys.argv[2]) if len(sys.argv) > 2 else 500_000
random.seed(0)
words = "order shipped delayed refund customer called again thanks".split()


def free_text(digit_frac: float) -> list[str]:
    out = []
    for _ in range(n):
        t = " ".join(random.choices(words, k=8))
        if random.random() < digit_frac:
            t += f" ref {random.randint(1000, 99999999)}"
        out.append(t)
    out[::1000] = ["call 07911 123456 re refund"] * len(out[::1000])  # 0.1% PII
    return out


df = pd.DataFrame(
    {
        "no_digits": free_text(0),
        "30pct_digits": free_text(0.3),
        "all_digits": free_text(1.0),
        "status": random.choices(["open", "closed", "pending"], k=n),
    }
)
for col in df.columns:
    t = time.perf_counter()
    r = scan_dataframe(df, [col], engine=engine)
    print(f"{engine:7s}{col:14s}{time.perf_counter() - t:6.2f}s  ok={r.ok}")
