"""Checks the allocation per operation of a JMH run against the recorded baseline.

Usage: python3 check-allocation.py <jmh results.json> <allocation-baseline.json> [--write]

The allocation per operation (gc.alloc.rate.norm, from -prof gc) does not depend on the machine's speed, so unlike the
times it can gate a change on a shared CI runner. A benchmark fails when it allocates more than its baseline by more
than TOLERANCE (relative) plus SLACK bytes; benchmarks whose allocation depends on thread timing (the loopback ones,
where timers and feedback interleave with the measured path) only fail beyond LOOSE_TOLERANCE. A benchmark missing
from the baseline is reported and not checked. --write replaces the baseline with the run's figures.
"""
import json
import sys

TOLERANCE = 0.10
LOOSE_TOLERANCE = 0.50
SLACK = 64
LOOSE_PREFIXES = ("com.github.auties00.parley.it.",)


def key(result):
    params = result.get("params") or {}
    suffix = ",".join(f"{name}={params[name]}" for name in sorted(params))
    return result["benchmark"] + (f"[{suffix}]" if suffix else "")


def allocations(path):
    with open(path, encoding="utf8") as file:
        results = json.load(file)
    figures = {}
    for result in results:
        secondary = result.get("secondaryMetrics", {}).get("gc.alloc.rate.norm")
        if secondary is not None:
            figures[key(result)] = secondary["score"]
    return figures


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    run = allocations(sys.argv[1])
    if not run:
        raise SystemExit("no allocation figures in " + sys.argv[1] + "; was the run made with -prof gc?")
    if "--write" in sys.argv[3:]:
        with open(sys.argv[2], "w", encoding="utf8") as file:
            json.dump({name: round(value, 1) for name, value in sorted(run.items())}, file, indent=2)
            file.write("\n")
        print(f"wrote {len(run)} baselines to {sys.argv[2]}")
        return
    with open(sys.argv[2], encoding="utf8") as file:
        baseline = json.load(file)
    failures = []
    for name, value in sorted(run.items()):
        expected = baseline.get(name)
        if expected is None:
            print(f"  new      {name}: {value:.0f} B/op (no baseline)")
            continue
        tolerance = LOOSE_TOLERANCE if name.startswith(LOOSE_PREFIXES) else TOLERANCE
        limit = expected * (1 + tolerance) + SLACK
        status = "OK" if value <= limit else "REGRESSED"
        print(f"  {status:9}{name}: {value:.0f} B/op (baseline {expected:.0f}, limit {limit:.0f})")
        if value > limit:
            failures.append(name)
    if failures:
        raise SystemExit(f"{len(failures)} benchmark(s) allocate more than their baseline: " + ", ".join(failures))
    print(f"{len(run)} benchmarks within their allocation baseline")


if __name__ == "__main__":
    main()
