import argparse
from pathlib import Path

from detecttrie import DetectTrie
from iptrie import ip_prefix_to_bits


def classify_update(detect_trie, prefix, origin_asn):
    """Detect if BGP update is a hijack
    
    DetectTrie stores legal AS set, not confidence scores
    - If prefix exists and origin_asn in legal set => legit
    - If prefix exists but origin_asn not in legal set => hijack
    - If prefix does not exist => unknown_prefix
    """
    bits = ip_prefix_to_bits(prefix)
    legit_as_set = detect_trie.search(bits)

    if legit_as_set is None:
        return "unknown_prefix", None

    origin_asn = int(origin_asn)
    if origin_asn in legit_as_set:
        return "legit", None
    else:
        return "hijack", None


def main():
    parser = argparse.ArgumentParser(description="Step 4: Detect hijacking using DetectTrie")
    parser.add_argument("--detecttrie", type=str, required=True,
                        help="DetectTrie filename (will be loaded from ./Detect_trie/)")
    parser.add_argument("--updates", type=str,
                        help="Path to updates file (JSON with prefix and origin fields)")
    args = parser.parse_args()

    detecttrie_path = Path("./Detect_trie") / Path(args.detecttrie).name
    dt = DetectTrie.load(str(detecttrie_path))

    if args.updates:
        import json
        with open(args.updates) as f:
            updates = json.load(f)
    else:
        print("Warning: No updates file provided. Using empty updates list.")
        updates = []

    hijacks = []
    for u in updates:
        try:
            status, _ = classify_update(dt, u["prefix"], u["origin"])
            line = f"{u['prefix']} origin={u['origin']} => {status}"
            print(line)
            if status == "hijack":
                hijacks.append({"prefix": u["prefix"], "origin": int(u["origin"])})
        except Exception as e:
            print(f"{u['prefix']} origin={u['origin']} => error: {e}")

    print(f"hijack_events={len(hijacks)}")


if __name__ == "__main__":
    main()
