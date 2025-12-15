import argparse
import random
from pathlib import Path

from iptrie import IPTrie
from cloud_uncertainty import calculate_uncertainty, compute_cloud_params, save_json


def compute_uncertainty_for_trie(trie, n_sim=1000, seed=0):
    """Calculate uncertainty for all P/O pairs in IPTrie"""
    po_pairs = trie.collect_po_pairs()
    cloud_params = compute_cloud_params(
        po_pairs,
        n_bootstrap=200,
        seed=seed,
        only_rib_for_space_and_source=True,
    )

    rng = random.Random(int(seed) + 12345)
    scored = []
    for po in po_pairs:
        # calculate_uncertainty now returns a dictionary
        unc_info = calculate_uncertainty(po, cloud_params, n_sim=n_sim, rng=rng)
        
        item = dict(po)
        item["time_uncertainty"] = round(unc_info["time_uncertainty"], 6)
        item["space_uncertainty"] = round(unc_info["space_uncertainty"], 6)
        item["source_uncertainty"] = round(unc_info["source_uncertainty"], 6)
        item["total_uncertainty"] = round(unc_info["total_uncertainty"], 6)
        item["confidence"] = round(1.0 - unc_info["total_uncertainty"], 6)
        scored.append(item)

    return cloud_params, scored


def main():
    parser = argparse.ArgumentParser(description="Step 2: Calculate cloud model uncertainty")
    parser.add_argument("--iptrie", type=str, required=True,
                        help="Path to IPTrie file")
    parser.add_argument("--output-dir", type=str, required=False,
                        help="Output directory (deprecated, outputs to ./IPtrie/ by default)")
    parser.add_argument("--n-sim", type=int, default=200,
                        help="Number of simulations for normal sampling")
    parser.add_argument("--seed", type=int, default=0,
                        help="Random seed")
    args = parser.parse_args()

    out_dir = Path("./IPtrie")
    out_dir.mkdir(parents=True, exist_ok=True)

    trie = IPTrie.load_from_file(args.iptrie)
    cloud_params, scored = compute_uncertainty_for_trie(trie, n_sim=args.n_sim, seed=args.seed)

    params_path = out_dir / "cloud_params.json"
    scored_path = out_dir / "po_scores.json"

    save_json(cloud_params, params_path)
    save_json(scored, scored_path)

    print(f"Cloud params saved to: {params_path}")
    print(f"P/O scores saved to: {scored_path}")
    print(f"po_pairs={len(scored)}")


if __name__ == "__main__":
    main()
