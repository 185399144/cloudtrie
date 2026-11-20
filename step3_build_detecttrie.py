"""Step 3: Filter trusted P/O mappings (u < th_pro) and construct DetectTrie."""

import argparse
import json
from pathlib import Path

from cloud_uncertainty import DEFAULT_TH_PRO
from detecttrie import DetectTrie


def _resolve_output_path(output_arg: str, default_dir: Path) -> Path:
    p = Path(output_arg)
    if p.parent == Path(".") and not output_arg.startswith(("./", ".\\")):
        return default_dir / p.name
    return p


def build_detecttrie_from_scores(scores, th_pro: float = DEFAULT_TH_PRO):
    """Build DetectTrie from scored P/O mappings with total_uncertainty < th_pro."""
    dt = DetectTrie()
    inserted = 0
    for item in scores:
        if "total_uncertainty" in item:
            is_trusted = float(item["total_uncertainty"]) < float(th_pro)
        else:
            is_trusted = float(item["confidence"]) > (1.0 - float(th_pro))
        if is_trusted:
            dt.insert(item["prefix_bits"], item["origin"])
            inserted += 1
    return dt, inserted


def main():
    parser = argparse.ArgumentParser(
        description="Step 3: Build DetectTrie from P/O uncertainty scores"
    )
    parser.add_argument(
        "--scores",
        type=str,
        required=True,
        help="Path to po_scores.json produced by step2_cloud_uncertainty.py",
    )
    parser.add_argument(
        "--th-pro",
        type=float,
        default=DEFAULT_TH_PRO,
        help="Uncertainty threshold th_pro; pairs with u < th_pro are trusted (default: 0.40)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Optional confidence threshold alias (equivalent to th_pro = 1 - threshold)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./DetectTrie/detecttrie.dat",
        help="Output path for DetectTrie file (default: ./DetectTrie/detecttrie.dat)",
    )
    args = parser.parse_args()

    th_pro = (1.0 - args.threshold) if args.threshold is not None else args.th_pro

    with open(args.scores, "r", encoding="utf-8") as f:
        scores = json.load(f)

    dt, inserted = build_detecttrie_from_scores(scores, th_pro=th_pro)
    out_path = _resolve_output_path(args.output, Path("./DetectTrie"))
    dt.save(out_path)

    print(f"DetectTrie saved to: {out_path}")
    print(f"th_pro={th_pro:.4f}, inserted={inserted}, moas_prefixes={len(dt.conflict_log)}")


if __name__ == "__main__":
    main()
