"""Step 4: Online BGP hijack detection and lazy DetectTrie update.

Implements Section IV-D of CloudTrie:
  1. Fast O(L) exact lookup in DetectTrie.
  2. When ModelTrie (--iptrie) and cloud parameters (--cloud-params) are provided,
     newly emerging P/O pairs are evaluated in real time via the one-sided rule-matrix
     cloud model (updating origin counters N(o) and Q(o)).
     - Pairs with u < th_pro are accepted as legitimate new mappings and buffered for
       lazy update into DetectTrie once pending count exceeds th_update.
     - Pairs with u >= th_pro are classified by RFC 6811 Cover/Match rules against
       DetectTrie into Valid, Hijack, Sub_Hijack, or NotFound, with per-dimension
       deviations explaining which evidence is missing.
"""

import argparse
import json
from pathlib import Path

from cloud_uncertainty import DEFAULT_TH_PRO, calculate_uncertainty, load_json, save_json
from detecttrie import DetectTrie
from iptrie import IPTrie, ip_prefix_to_bits, normalize_asn


class OnlineDetector:
    """Dual-Trie online detector combining DetectTrie with live ModelTrie reasoning."""

    def __init__(
        self,
        detect_trie: DetectTrie,
        model_trie: IPTrie = None,
        cloud_params: dict = None,
        th_pro: float = DEFAULT_TH_PRO,
        th_update: int = 100,
    ):
        self.detect_trie = detect_trie
        self.model_trie = model_trie
        self.cloud_params = cloud_params
        self.th_pro = float(th_pro)
        self.th_update = int(th_update)
        self.pending_updates = {}  # (prefix_bits, origin_asn) -> True
        self.lazy_flushes = 0
        self.accepted_new_pairs = 0

    def flush_pending(self) -> int:
        """Apply buffered legitimate new P/O pairs to DetectTrie."""
        if not self.pending_updates:
            return 0
        count = len(self.pending_updates)
        for prefix_bits, origin in self.pending_updates:
            self.detect_trie.insert(prefix_bits, origin)
        self.pending_updates.clear()
        self.lazy_flushes += 1
        return count

    def classify_update(self, prefix: str, origin_asn, as_path=None) -> dict:
        """Classify a single BGP announcement and apply online lazy update rules."""
        bits = ip_prefix_to_bits(prefix)
        origin = normalize_asn(origin_asn)

        # Fast path: exact match already trusted in DetectTrie or pending lazy insertion
        exact_set = self.detect_trie.search(bits)
        if (exact_set and origin in exact_set) or (bits, origin) in self.pending_updates:
            return {
                "prefix": prefix,
                "origin": origin,
                "status": "valid",
                "matched_prefix_len": len(bits),
                "expected_origins": sorted(exact_set) if exact_set else [origin],
                "uncertainty": None,
                "certainty": None,
            }

        unc_info = None
        if self.model_trie is not None and self.cloud_params is not None:
            live_po = self.model_trie.evaluate_live_pair(
                prefix, origin, as_path=as_path, update_counters=True
            )
            unc_info = calculate_uncertainty(live_po, self.cloud_params, stochastic=False)
            if unc_info["total_uncertainty"] < self.th_pro:
                self.pending_updates[(bits, origin)] = True
                self.accepted_new_pairs += 1
                if len(self.pending_updates) > self.th_update:
                    self.flush_pending()
                return {
                    "prefix": prefix,
                    "origin": origin,
                    "status": "valid",
                    "accepted_as_new": True,
                    "uncertainty": round(unc_info["total_uncertainty"], 6),
                    "certainty": round(unc_info["certainty"], 6),
                    "deviations": {
                        "delta_t": round(unc_info["delta_t"], 6),
                        "delta_r": round(unc_info["delta_r"], 6),
                        "delta_m": round(unc_info["delta_m"], 6),
                    },
                }

        status, expected_set, matched_len = self.detect_trie.classify(bits, origin)
        result = {
            "prefix": prefix,
            "origin": origin,
            "status": status,
            "matched_prefix_len": matched_len,
            "expected_origins": sorted(expected_set),
        }
        if unc_info is not None:
            result["uncertainty"] = round(unc_info["total_uncertainty"], 6)
            result["certainty"] = round(unc_info["certainty"], 6)
            result["rule_temporal"] = round(unc_info["rule_temporal"], 6)
            result["rule_spatial_source"] = round(unc_info["rule_spatial_source"], 6)
            result["deviations"] = {
                "delta_t": round(unc_info["delta_t"], 6),
                "delta_r": round(unc_info["delta_r"], 6),
                "delta_m": round(unc_info["delta_m"], 6),
            }
        return result


def classify_update(detect_trie: DetectTrie, prefix: str, origin_asn):
    """Lightweight DetectTrie-only classification helper (backward compatible)."""
    bits = ip_prefix_to_bits(prefix)
    status, expected_set, _ = detect_trie.classify(bits, normalize_asn(origin_asn))
    return status, sorted(expected_set) if expected_set else None


def _resolve_input_path(path_arg: str, fallback_dir: Path) -> Path:
    p = Path(path_arg)
    if p.exists():
        return p
    alt = fallback_dir / p.name
    return alt if alt.exists() else p


def main():
    parser = argparse.ArgumentParser(
        description="Step 4: Detect BGP prefix/sub-prefix hijacks using CloudTrie"
    )
    parser.add_argument(
        "--detecttrie",
        type=str,
        required=True,
        help="Path to DetectTrie file produced by step3_build_detecttrie.py",
    )
    parser.add_argument(
        "--updates",
        type=str,
        default=None,
        help="Path to BGP updates JSON file (list of {prefix, origin[, as_path]})",
    )
    parser.add_argument(
        "--iptrie",
        type=str,
        default=None,
        help="Optional ModelTrie (IPTrie) path for live evaluation of newly emerging P/O pairs",
    )
    parser.add_argument(
        "--cloud-params",
        type=str,
        default=None,
        help="Optional cloud_params.json path (used together with --iptrie)",
    )
    parser.add_argument(
        "--th-pro",
        type=float,
        default=DEFAULT_TH_PRO,
        help="Uncertainty threshold th_pro for accepting new pairs (default: 0.40)",
    )
    parser.add_argument(
        "--th-update",
        type=int,
        default=100,
        help="Lazy update threshold th_update for flushing pending pairs into DetectTrie (default: 100)",
    )
    parser.add_argument(
        "--save-updated",
        type=str,
        default=None,
        help="Optional path to save DetectTrie after flushing accepted online updates",
    )
    parser.add_argument(
        "--report",
        type=str,
        default=None,
        help="Optional JSON output path to save full detection results and anomaly alerts",
    )
    args = parser.parse_args()

    dt_path = _resolve_input_path(args.detecttrie, Path("./DetectTrie"))
    dt = DetectTrie.load(dt_path)

    model_trie = None
    cloud_params = None
    if args.iptrie and args.cloud_params:
        mt_path = _resolve_input_path(args.iptrie, Path("./IPtrie"))
        cp_path = _resolve_input_path(args.cloud_params, Path("./IPtrie"))
        model_trie = IPTrie.load_from_file(mt_path)
        cloud_params = load_json(cp_path)
    elif args.iptrie or args.cloud_params:
        print("Warning: provide both --iptrie and --cloud-params to enable live ModelTrie evaluation.")

    detector = OnlineDetector(
        detect_trie=dt,
        model_trie=model_trie,
        cloud_params=cloud_params,
        th_pro=args.th_pro,
        th_update=args.th_update,
    )

    if args.updates:
        with open(args.updates, "r", encoding="utf-8") as f:
            updates = json.load(f)
    else:
        print("Warning: No updates file provided. Using empty updates list.")
        updates = []

    results = []
    alerts = []
    for u in updates:
        try:
            res = detector.classify_update(
                u["prefix"], u["origin"], as_path=u.get("as_path")
            )
            results.append(res)
            u_str = f" u={res['uncertainty']:.4f}" if res.get("uncertainty") is not None else ""
            print(f"{res['prefix']} origin={res['origin']} => {res['status']}{u_str}")
            if res["status"] in ("hijack", "sub_hijack"):
                alerts.append(res)
        except Exception as exc:
            print(f"{u.get('prefix')} origin={u.get('origin')} => error: {exc}")

    if args.save_updated:
        detector.flush_pending()
        dt.save(args.save_updated)
        print(f"Updated DetectTrie saved to: {args.save_updated}")

    if args.report:
        save_json(
            {
                "total_updates": len(results),
                "alert_count": len(alerts),
                "accepted_new_pairs": detector.accepted_new_pairs,
                "lazy_flushes": detector.lazy_flushes,
                "alerts": alerts,
                "results": results,
            },
            args.report,
        )
        print(f"Detection report saved to: {args.report}")

    print(
        f"total_updates={len(results)}, hijack_events={len(alerts)}, "
        f"accepted_new_pairs={detector.accepted_new_pairs}"
    )


if __name__ == "__main__":
    main()
