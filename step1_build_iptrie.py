"""Step 1: Build ModelTrie (IPTrie) from BGP RIB, RPKI ROA, IRR, AS-rel, and AS2Org."""

import argparse
from pathlib import Path

from build_iptrie import build_iptrie_from_real_data
from iptrie import DEFAULT_WINDOW_DAYS


def _resolve_output_path(output_arg: str, default_dir: Path) -> Path:
    p = Path(output_arg)
    if p.parent == Path(".") and not output_arg.startswith(("./", ".\\")):
        return default_dir / p.name
    return p


def main():
    parser = argparse.ArgumentParser(
        description="Step 1: Build ModelTrie (IPTrie) from multi-source BGP routing data"
    )
    parser.add_argument(
        "--rib-file",
        type=str,
        required=True,
        help="Path to a RIB file or a directory of multi-day RIB snapshots",
    )
    parser.add_argument(
        "--roa-dir",
        type=str,
        default=None,
        help="Path to RPKI ROA directory or file (CSV / .csv.xz / TSV)",
    )
    parser.add_argument(
        "--irr-dir",
        type=str,
        default=None,
        help="Path to IRR directory or file (RPSL / .gz / TSV)",
    )
    parser.add_argument(
        "--as-rel",
        type=str,
        default=None,
        help="Path to CAIDA AS relationships file or directory (as-rel2.txt)",
    )
    parser.add_argument(
        "--as-org",
        type=str,
        default=None,
        help="Path to CAIDA AS-to-Organization file or directory (as-org2info.txt.gz)",
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=DEFAULT_WINDOW_DAYS,
        help="Observation window length d in days (default: 5)",
    )
    parser.add_argument(
        "--end-date",
        type=str,
        default=None,
        help="Window end date YYYYMMDD (defaults to latest RIB snapshot date)",
    )
    parser.add_argument(
        "--ip-version",
        type=int,
        choices=(4, 6),
        default=4,
        help="IP protocol version (4 or 6; default: 4)",
    )
    parser.add_argument(
        "--bgpdump",
        type=str,
        default=None,
        help="Path to bgpdump binary (auto-detected from PATH if omitted)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./IPtrie/iptrie.dat",
        help="Output path for ModelTrie (IPTrie) file (default: ./IPtrie/iptrie.dat)",
    )
    args = parser.parse_args()

    print("Building ModelTrie (IPTrie) from routing data...")
    trie = build_iptrie_from_real_data(
        rib_file=args.rib_file,
        roa_dir=args.roa_dir,
        irr_dir=args.irr_dir,
        as_rel_path=args.as_rel,
        as_org_path=args.as_org,
        bgpdump_path=args.bgpdump,
        window_days=args.window_days,
        end_date=args.end_date,
        ip_version=args.ip_version,
    )

    # Pre-populate origin consistency counters N(o), Q(o) and delegation cache before saving
    po_pairs = trie.collect_po_pairs()
    out_path = _resolve_output_path(args.output, Path("./IPtrie"))
    trie.save_to_file(out_path)

    print(f"ModelTrie (IPTrie) saved to: {out_path}")
    print(f"po_pairs={len(po_pairs)}")


if __name__ == "__main__":
    main()
