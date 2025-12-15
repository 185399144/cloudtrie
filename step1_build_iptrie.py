import argparse
from pathlib import Path

from build_iptrie import build_iptrie_from_real_data


def main():
    parser = argparse.ArgumentParser(description="Step 1: Build IPTrie from real data")
    parser.add_argument("--rib-file", type=str, required=True,
                        help="Path to RIB file (e.g., /mnt/data/hijack-2017-01-5/rrc00_updates.20170105.1200.gz)")
    parser.add_argument("--roa-dir", type=str, required=True,
                        help="Directory with ROA files (e.g., /mnt/data/afrinic-roa-24/)")
    parser.add_argument("--irr-dir", type=str, required=True,
                        help="Directory with IRR files (e.g., /mnt/data/IRR/)")
    parser.add_argument("--output", type=str, required=True,
                        help="Output filename for IPTrie file (will be saved to ./IPtrie/)")
    parser.add_argument("--bgpdump", type=str, default="/mnt/data/bgpd/bgpdump",
                        help="Path to bgpdump binary")

    args = parser.parse_args()

    print("Building IPTrie from real data...")
    trie = build_iptrie_from_real_data(
        rib_file=args.rib_file,
        roa_dir=args.roa_dir,
        irr_dir=args.irr_dir,
        bgpdump_path=args.bgpdump,
    )

    out_path = Path(args.output)
    out_dir = Path("./IPtrie")
    out_dir.mkdir(parents=True, exist_ok=True)
    iptrie_file = out_dir / out_path.name
    trie.save_to_file(iptrie_file)
    po_count = len(trie.collect_po_pairs())
    print(f"IPTrie saved to: {iptrie_file}")
    print(f"po_pairs={po_count}")


if __name__ == "__main__":
    main()
