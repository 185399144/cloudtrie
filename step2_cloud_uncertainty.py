"""Step 2: Estimate anchor-based cloud parameters and compute P/O uncertainty degrees."""

import argparse
import random
from pathlib import Path

from cloud_uncertainty import (
    DEFAULT_SOURCE_EN,
    calculate_uncertainty,
    compute_cloud_params,
    save_json,
)
from iptrie import IPTrie


def compute_uncertainty_for_trie(
    trie: IPTrie,
    en_m: float = DEFAULT_SOURCE_EN,
    stochastic: bool = False,
    n_sim: int = 200,
    seed: int = 0,
):
    """Extract normalized features, fit anchor clouds, and score all P/O pairs."""
    po_pairs = trie.collect_po_pairs()
    cloud_params = compute_cloud_params(po_pairs, en_m=en_m)

    rng = random.Random(int(seed) + 12345) if stochastic else None
    scored = []
    for po in po_pairs:
        unc_info = calculate_uncertainty(
            po,
            cloud_params,
            stochastic=stochastic,
            n_sim=n_sim,
            rng=rng,
        )
        item = dict(po)
        item["delta_t"] = round(unc_info["delta_t"], 6)
        item["delta_r"] = round(unc_info["delta_r"], 6)
        item["delta_m"] = round(unc_info["delta_m"], 6)
        item["rule_temporal"] = round(unc_info["rule_temporal"], 6)
        item["rule_spatial_source"] = round(unc_info["rule_spatial_source"], 6)
        item["certainty"] = round(unc_info["certainty"], 6)
        item["confidence"] = item["certainty"]
        item["total_uncertainty"] = round(unc_info["total_uncertainty"], 6)
        scored.append(item)

    return cloud_params, scored


def main():
    parser = argparse.ArgumentParser(
        description="Step 2: Fit anchor cloud model and compute P/O uncertainty degrees"
    )
    parser.add_argument(
        "--iptrie",
        type=str,
        required=True,
        help="Path to ModelTrie (IPTrie) file produced by step1_build_iptrie.py",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./IPtrie",
        help="Directory to write cloud_params.json and po_scores.json (default: ./IPtrie)",
    )
    parser.add_argument(
        "--en-m",
        type=float,
        default=DEFAULT_SOURCE_EN,
        help="Preset entropy En_m for the data-source gate (default: 0.15)",
    )
    parser.add_argument(
        "--stochastic",
        action="store_true",
        help="Enable Monte Carlo cloud-droplet simulation (default: deterministic En' = En)",
    )
    parser.add_argument(
        "--n-sim",
        type=int,
        default=200,
        help="Number of cloud droplets when --stochastic is set (default: 200)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Random seed when --stochastic is set (default: 0)",
    )
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    trie = IPTrie.load_from_file(args.iptrie)
    cloud_params, scored = compute_uncertainty_for_trie(
        trie,
        en_m=args.en_m,
        stochastic=args.stochastic,
        n_sim=args.n_sim,
        seed=args.seed,
    )

    params_path = out_dir / "cloud_params.json"
    scored_path = out_dir / "po_scores.json"
    save_json(cloud_params, params_path)
    save_json(scored, scored_path)

    print(f"Cloud params saved to: {params_path}")
    print(f"P/O scores saved to: {scored_path}")
    print(f"po_pairs={len(scored)}")
    print(
        "Anchor cloud params: "
        f"time=(Ex={cloud_params['time']['Ex']:.4f}, En={cloud_params['time']['En']:.4f}, He={cloud_params['time']['He']:.4f}), "
        f"space=(Ex={cloud_params['space']['Ex']:.4f}, En={cloud_params['space']['En']:.4f}, He={cloud_params['space']['He']:.4f}), "
        f"source=(Ex={cloud_params['source']['Ex']:.2f}, En={cloud_params['source']['En']:.2f}, He={cloud_params['source']['He']:.2f})"
    )


if __name__ == "__main__":
    main()
