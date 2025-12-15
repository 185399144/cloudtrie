import json
import math
import random
import statistics
from pathlib import Path


_EPS = 1e-12


def _safe_mean(values):
    if not values:
        return 0.0
    return float(statistics.mean(values))


def _safe_pstdev(values):
    if not values:
        return 0.0
    if len(values) < 2:
        return 0.0
    return float(statistics.pstdev(values))


def bootstrap_he(values, n_bootstrap=200, seed=0):
    if not values:
        return 0.0
    if len(values) < 2:
        return 0.0

    rng = random.Random(seed)
    n = len(values)
    en_samples = []
    for _ in range(int(n_bootstrap)):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        en_samples.append(_safe_pstdev(sample))

    he = _safe_pstdev(en_samples)
    return float(he)


def estimate_cloud_params(values, n_bootstrap=200, seed=0):
    ex = _safe_mean(values)
    en = _safe_pstdev(values)
    he = bootstrap_he(values, n_bootstrap=n_bootstrap, seed=seed)

    if en < _EPS:
        en = _EPS
    if he < 0.0:
        he = 0.0

    return {"Ex": float(ex), "En": float(en), "He": float(he)}


def compute_cloud_params(po_pairs, n_bootstrap=200, seed=0, only_rib_for_space_and_source=True):
    """Compute cloud model parameters
    
    Time persistence: use all P/O pairs
    Space and source consistency: use only P/O pairs with RIB data
    """
    # Time persistence uses all data
    time_values = [float(po["time_persistence"]) for po in po_pairs]

    # Space and source consistency use only RIB data
    if only_rib_for_space_and_source:
        space_values = [float(po["space_consistency"]) for po in po_pairs if po.get("has_rib")]
        member_values = [float(po["source_consistency"]) for po in po_pairs if po.get("has_rib")]
    else:
        space_values = [float(po["space_consistency"]) for po in po_pairs]
        member_values = [float(po["source_consistency"]) for po in po_pairs]

    params = {
        "time": estimate_cloud_params(time_values, n_bootstrap=n_bootstrap, seed=seed + 11),
        "space": estimate_cloud_params(space_values, n_bootstrap=n_bootstrap, seed=seed + 13),
        "membership": estimate_cloud_params(member_values, n_bootstrap=n_bootstrap, seed=seed + 17),
        "meta": {
            "n_po": int(len(po_pairs)),
            "n_rib": int(len([po for po in po_pairs if po.get("has_rib")])),
            "n_space": int(len(space_values)),
            "n_membership": int(len(member_values)),
            "only_rib_for_space_and_source": bool(only_rib_for_space_and_source),
        },
    }
    return params


def _simulate_membership(x, ex, en, he, n_sim, rng):
    en = max(float(en), _EPS)
    he = max(float(he), 0.0)

    acc = 0.0
    for _ in range(int(n_sim)):
        en_sample = rng.gauss(en, he)
        en_sample = abs(en_sample)
        en_sample = max(en_sample, _EPS)
        acc += math.exp(-((x - ex) ** 2) / (2.0 * (en_sample ** 2)))

    return acc / float(n_sim)


def calculate_uncertainty(po, cloud_params, n_sim=1000, rng=None):
    """Calculate uncertainty for a single P/O pair
    
    - Uses cloud droplet simulation
    """
    if rng is None:
        rng = random.Random(0)

    x_time = float(po["time_persistence"])
    x_space = float(po["space_consistency"])
    x_source = float(po["source_consistency"])

    p_time = cloud_params["time"]
    p_space = cloud_params["space"]
    p_source = cloud_params["membership"]

    # Time uncertainty
    mu_time = _simulate_membership(x_time, p_time["Ex"], p_time["En"], p_time["He"], n_sim=n_sim, rng=rng)
    time_uncertainty = 1.0 - mu_time

    # Space uncertainty
    mu_space = _simulate_membership(x_space, p_space["Ex"], p_space["En"], p_space["He"], n_sim=n_sim, rng=rng)
    space_uncertainty = 1.0 - mu_space

    # Source uncertainty - half-cloud model
    # When source consistency >= Ex, uncertainty = 0
    if x_source >= p_source["Ex"]:
        source_uncertainty = 0.0
    else:
        mu_source = _simulate_membership(x_source, p_source["Ex"], p_source["En"], p_source["He"], n_sim=n_sim, rng=rng)
        source_uncertainty = 1.0 - mu_source

    # Total uncertainty 
    total_uncertainty = (time_uncertainty + space_uncertainty + source_uncertainty) / 3.0

    return {
        "time_consistency": x_time,
        "space_consistency": x_space,
        "source_consistency": x_source,
        "time_uncertainty": float(time_uncertainty),
        "space_uncertainty": float(space_uncertainty),
        "source_uncertainty": float(source_uncertainty),
        "total_uncertainty": float(total_uncertainty),
    }


def save_json(obj, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)
