"""Anchor-based backward normal cloud estimation and one-sided rule-matrix reasoning.

Implements Section IV-C of CloudTrie:
  1. Backward cloud parameter estimation (Ex, En, He) on anchor drops:
       Ex = (1/a) * sum(x_i)
       En = sqrt(pi/2) * (1/a) * sum(|x_i - Ex|)
       He = sqrt(max(B^2 - En^2, 0))
     where:
       - Temporal anchors (s^t): BGP-observed P/O pairs without competing origins.
       - Spatial anchors (s^r): BGP-observed P/O pairs with competing origins persisting
         across the full observation window.
       - Data source gate (s^m): fixed Ex_m = 0.5, En_m = 0.15, He_m = 0.0.
  2. One-sided rule-matrix cloud reasoning (W = [[1, 0, 0], [0, 1, 1]]):
       delta_k = max(Ex_k - s^k, 0)
       g_1 = exp(-delta_t^2 / (2 * En'_t^2))
       g_2 = exp(-delta_r^2 / (2 * En'_r^2) - delta_m^2 / (2 * En'_m^2))
       certainty y = max(g_1, g_2),  uncertainty u = 1 - y.
     During online detection, En' is fixed to En (stochastic=False) for deterministic
     inference while He characterizes the dispersion of the cloud.
"""

import json
import math
import random
from pathlib import Path


_EPS = 1e-6
_SQRT_PI_2 = math.sqrt(math.pi / 2.0)

DEFAULT_SOURCE_EX = 0.5
DEFAULT_SOURCE_EN = 0.15
DEFAULT_SOURCE_HE = 0.0
DEFAULT_TH_PRO = 0.40


def estimate_cloud_params(values):
    """Analytical backward normal cloud generator (Eqs. 5-8)."""
    vals = [float(v) for v in values]
    n = len(vals)
    if n == 0:
        return {"Ex": 0.0, "En": _EPS, "He": 0.0}

    ex = sum(vals) / n
    en = _SQRT_PI_2 * (sum(abs(x - ex) for x in vals) / n)
    if n > 1:
        var = sum((x - ex) ** 2 for x in vals) / (n - 1)
    else:
        var = 0.0
    he = math.sqrt(max(var - en * en, 0.0))

    return {
        "Ex": float(ex),
        "En": float(max(en, _EPS)),
        "He": float(he),
    }


def compute_cloud_params(po_pairs, en_m: float = DEFAULT_SOURCE_EN):
    """Estimate cloud parameters (Ex, En, He) from anchor drops.

    Anchor selection:
      - time (s^t): BGP-observed pairs without competing origins.
      - space (s^r): BGP-observed pairs with competing origins observed across the
        full d-day window (with graceful fallback for single-day or tiny datasets).
      - source (s^m): fixed gate Ex_m = 0.5, En_m = en_m, He_m = 0.0.
    """
    rib_pairs = [po for po in po_pairs if po.get("has_rib")]

    anchor_t = [float(po["time_persistence"]) for po in rib_pairs if not po.get("has_comp")]
    if not anchor_t:
        anchor_t = [float(po["time_persistence"]) for po in rib_pairs] or [
            float(po["time_persistence"]) for po in po_pairs
        ]

    anchor_r = [
        float(po["space_consistency"])
        for po in rib_pairs
        if po.get("has_comp") and po.get("full_window", True)
    ]
    if not anchor_r:
        anchor_r = [float(po["space_consistency"]) for po in rib_pairs if po.get("has_comp")]
    if not anchor_r:
        anchor_r = [float(po["space_consistency"]) for po in rib_pairs]

    # Empirical source distribution recorded in metadata for descriptive reference only
    emp_m_vals = [
        float(po["source_consistency"])
        for po in po_pairs
        if po.get("has_rib") or po.get("rpki_status") == 1
    ]

    params = {
        "time": estimate_cloud_params(anchor_t),
        "space": estimate_cloud_params(anchor_r),
        "source": {
            "Ex": float(DEFAULT_SOURCE_EX),
            "En": float(max(en_m, _EPS)),
            "He": float(DEFAULT_SOURCE_HE),
        },
        "rule_matrix": [[1, 0, 0], [0, 1, 1]],
        "meta": {
            "n_po": int(len(po_pairs)),
            "n_rib": int(len(rib_pairs)),
            "n_anchor_time": int(len(anchor_t)),
            "n_anchor_space": int(len(anchor_r)),
            "empirical_source_cloud": estimate_cloud_params(emp_m_vals) if emp_m_vals else None,
        },
    }
    return params


def _sample_en(en: float, he: float, stochastic: bool, rng):
    en = max(float(en), _EPS)
    if not stochastic or he <= 0.0:
        return en
    return max(abs(rng.gauss(en, float(he))), _EPS)


def calculate_uncertainty(po, cloud_params, stochastic: bool = False, n_sim: int = 200, rng=None):
    """Evaluate one-sided rule-matrix certainty and uncertainty (Eqs. 9-10).

    Rule 1 (row [1, 0, 0]): temporal persistence alone -> trusts stably announced routes.
    Rule 2 (row [0, 1, 1]): joint spatial consistency & RPKI/IRR gate -> validates newly
                            emerging legitimate P/O pairs with low s^t.

    Returns a dictionary containing feature values, one-sided deviations, rule
    certainties, total certainty (y), and uncertainty degree (u = 1 - y).
    """
    x_t = float(po["time_persistence"])
    x_r = float(po["space_consistency"])
    x_m = float(po["source_consistency"])

    p_t = cloud_params["time"]
    p_r = cloud_params["space"]
    p_m = cloud_params.get("source", cloud_params.get("membership"))

    delta_t = max(float(p_t["Ex"]) - x_t, 0.0)
    delta_r = max(float(p_r["Ex"]) - x_r, 0.0)
    delta_m = max(float(p_m["Ex"]) - x_m, 0.0)

    runs = int(n_sim) if stochastic else 1
    if stochastic and rng is None:
        rng = random.Random(0)

    g1_acc = 0.0
    g2_acc = 0.0
    y_acc = 0.0
    for _ in range(runs):
        en_t = _sample_en(p_t["En"], p_t.get("He", 0.0), stochastic, rng)
        en_r = _sample_en(p_r["En"], p_r.get("He", 0.0), stochastic, rng)
        en_m = _sample_en(p_m["En"], p_m.get("He", 0.0), stochastic, rng)

        term_t = (delta_t * delta_t) / (2.0 * en_t * en_t)
        term_r = (delta_r * delta_r) / (2.0 * en_r * en_r)
        term_m = (delta_m * delta_m) / (2.0 * en_m * en_m)

        g1 = math.exp(-term_t)
        g2 = math.exp(-(term_r + term_m))
        g1_acc += g1
        g2_acc += g2
        y_acc += max(g1, g2)

    g1_mean = g1_acc / runs
    g2_mean = g2_acc / runs
    certainty = y_acc / runs
    uncertainty = 1.0 - certainty

    return {
        "time_consistency": x_t,
        "space_consistency": x_r,
        "source_consistency": x_m,
        "delta_t": float(delta_t),
        "delta_r": float(delta_r),
        "delta_m": float(delta_m),
        "rule_temporal": float(g1_mean),
        "rule_spatial_source": float(g2_mean),
        "certainty": float(certainty),
        "total_uncertainty": float(uncertainty),
    }


def save_json(obj, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)
