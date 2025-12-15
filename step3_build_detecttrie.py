import argparse
from pathlib import Path
import json
from detecttrie import DetectTrie


def build_detecttrie_from_scores(scores, threshold=0.6):
    """Build DetectTrie from P/O scores
    
    Only insert P/O pairs with confidence >= threshold
    DetectTrie stores legal AS set, not confidence scores
    """
    dt = DetectTrie()
    inserted = 0
    for item in scores:
        if item["confidence"] >= threshold:
            # insert(binary_prefix, source_as) - stores AS set only
            dt.insert(item["prefix_bits"], item["origin"])
            inserted += 1
    return dt, inserted


def main():
    parser = argparse.ArgumentParser(description="Step 3: Build DetectTrie from P/O scores")
    parser.add_argument("--scores", type=str, required=True,
                        help="Path to P/O scores JSON file")
    parser.add_argument("--threshold", type=float, default=0.6,
                        help="Confidence threshold for insertion")
    parser.add_argument("--output", type=str, required=True,
                        help="Output filename for DetectTrie file (will be saved to ./Detect_trie/)")
    args = parser.parse_args()

    with open(args.scores) as f:
        scores = json.load(f)

    dt, inserted = build_detecttrie_from_scores(scores, threshold=args.threshold)
    
    out_dir = Path("./Detect_trie")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / Path(args.output).name
    dt.save(str(out_path))

    print(f"DetectTrie saved to: {out_path}")
    print(f"inserted={inserted}")


if __name__ == "__main__":
    main()
