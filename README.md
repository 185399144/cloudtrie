# CloudTrie: BGP Prefix Hijacking Detection for Uncertain Routing Data

A lightweight, interpretable framework for building **ModelTrie** (`IPTrie`) from multi-source BGP routing data, quantifying Prefix/Origin (P/O) uncertainty via an anchor-calibrated one-sided normal cloud model, constructing **DetectTrie**, and performing online prefix/sub-prefix hijack detection with lazy updates.

## Directory Structure

```text
cloudtrie/
├── iptrie.py                    # ModelTrie (IPTrie) structure, AS-path cleaning, and [0, 1] feature extraction
├── build_iptrie.py              # Parsers for BGP RIB, RPKI ROA, IRR, CAIDA AS-rel, and CAIDA AS2Org
├── cloud_uncertainty.py         # Anchor-drop backward cloud generator & one-sided rule-matrix reasoning
├── detecttrie.py                # DetectTrie structure with RFC 6811 Cover/Match lookup
├── step1_build_iptrie.py        # Step 1: Build ModelTrie (IPTrie)
├── step2_cloud_uncertainty.py   # Step 2: Estimate anchor cloud parameters & score P/O uncertainty
├── step3_build_detecttrie.py    # Step 3: Filter trusted mappings (u < th_pro) & build DetectTrie
├── step4_detect.py              # Step 4: Online hijack/sub-hijack detection & lazy DetectTrie update
├── data/data/                   # Labeled BGP hijack benchmark datasets
├── rib_data/                    # Directory for BGP RIB snapshots
├── rpki_data/                   # Directory for RPKI ROA files
├── irr_data/                    # Directory for IRR route/route6 files
├── asrel_data/                  # Directory for CAIDA AS relationship files
├── asorg_data/                  # Directory for CAIDA AS-to-Organization files
├── IPtrie/                      # Default output directory for ModelTrie, cloud_params.json, po_scores.json
├── DetectTrie/                  # Default output directory for DetectTrie
├── requirements.txt
└── README.md
```

## Quick Start

### Complete 4-Step Workflow

```bash
# Step 1: Build ModelTrie (IPTrie) from multi-source data
python step1_build_iptrie.py \
  --rib-file ./rib_data/ \
  --roa-dir ./rpki_data/ \
  --irr-dir ./irr_data/ \
  --as-rel ./asrel_data/ \
  --as-org ./asorg_data/ \
  --output ./IPtrie/iptrie.dat

# Step 2: Fit anchor cloud model and compute P/O uncertainty degrees
python step2_cloud_uncertainty.py \
  --iptrie ./IPtrie/iptrie.dat \
  --output-dir ./IPtrie

# Step 3: Build DetectTrie from trusted P/O pairs (u < th_pro, default 0.40)
python step3_build_detecttrie.py \
  --scores ./IPtrie/po_scores.json \
  --th-pro 0.40 \
  --output ./DetectTrie/detecttrie.dat

# Step 4: Online anomaly detection (with live ModelTrie evaluation & lazy update)
python step4_detect.py \
  --detecttrie ./DetectTrie/detecttrie.dat \
  --iptrie ./IPtrie/iptrie.dat \
  --cloud-params ./IPtrie/cloud_params.json \
  --updates ./updates.json \
  --th-pro 0.40 \
  --th-update 100
```

> **Note:** `--as-rel`, `--as-org`, `--roa-dir`, and `--irr-dir` are optional when partial data sources are used. When directories contain multiple dated snapshots, pass `--end-date YYYYMMDD` (or let Step 1 align automatically to the latest RIB date) to select the corresponding $d$-day window.

## Data Sources & Preprocessing

- **BGP RIB (`./rib_data/`)**: MRT snapshots (parsed via `bgpdump`) or pipe-delimited `bgpdump -m` text files across a sliding window of $d$ days (default $d=5$). Preprocessing removes private ASNs, decomposes aggregated `AS_SET`s, and collapses AS-path prepending.
- **RPKI ROA (`./rpki_data/`)**: CSV / `.csv.xz` / TSV files containing `IP Prefix`, `ASN`, and `Max Length` for RFC 6811 validation.
- **IRR (`./irr_data/`)**: RPSL text (`.gz` supported) containing `route`/`route6` and `origin` fields, or pre-parsed TSV files.
- **CAIDA AS Relationships (`./asrel_data/`)**: `as-rel2.txt` (provider-customer `-1` and peer-to-peer `0` edges).
- **CAIDA AS-to-Organization (`./asorg_data/`)**: `as-org2info.txt.gz` (or mapped TSV) identifying same-organization and sister ASes.

## Methodology Summary

### 1. Normalized P/O Features ($[0, 1]$)

For each P/O pair $(p, o)$, three benefit-type features are extracted in $[0, 1]$ (larger values indicate stronger legitimacy evidence):

1. **Temporal Persistence ($s^t$)**:
   $$s^t = \frac{h \cdot w_t^T}{\sum_{j=1}^{d} w_{t,j}}$$
   where $h \in \{0, 1\}^{1 \times d}$ records daily presence across the $d$-day window and $w_t = [1.0, 0.8, 0.6, 0.4, 0.2]$ (newest day first for $d=5$).
2. **Spatial Consistency ($s^r$)**:
   $$s^r = \min\left\{\max_{c}\,\rho(o, c),\ 1 - \frac{Q(o)}{N(o)}\right\}$$
   where $c$ ranges over competing origins covering $p$ in BGP RIB or RPKI, $\rho(o, c) \in [0, 1]$ measures organizational/delegation/business closeness (or $1$ if RPKI-valid or uncontested), $N(o)$ is the number of active prefixes announced by $o$, and $Q(o)$ is the number of prefixes whose competing origins are all unrelated to $o$ ($s^r = 0$ if not observed in BGP).
3. **Data Source Reliability ($s^m$)**:
   $$s^m = \frac{1}{2} + \frac{\omega_1 k_1 + \omega_2 k_2}{2(\omega_1 + \omega_2)}$$
   with $\omega_1 = 0.9$ (RPKI), $\omega_2 = 0.7$ (IRR), $k_1 \in \{-1, 0, 1\}$ (RFC 6811 invalid/not-found/valid), and $k_2 \in \{0, 1\}$ (IRR presence, forced to $0$ whenever $k_1 = -1$).

### 2. Anchor-Drop Backward Cloud & One-Sided Rule-Matrix Reasoning

- **Backward Cloud Estimation**: $(Ex, En, He)$ are estimated analytically on anchor drops:
  - $s^t$ anchors: BGP-observed pairs without competing origins.
  - $s^r$ anchors: BGP-observed pairs with competing origins persisting across all $d$ days.
  - $s^m$ gate: fixed $Ex_m = 0.50$, $En_m = 0.15$, $He_m = 0.0$.
- **One-Sided Rule-Matrix Reasoning**: With one-sided deviations $\delta_k = \max(Ex_k - s^k, 0)$ and rule matrix $\mathbf{W} = \begin{bmatrix}1 & 0 & 0\\ 0 & 1 & 1\end{bmatrix}$:
  $$\hat{y}_i = \max\left\{\exp\!\left(-\frac{\delta_t^2}{2En_t'^2}\right),\ \exp\!\left(-\frac{\delta_r^2}{2En_r'^2} - \frac{\delta_m^2}{2En_m'^2}\right)\right\}, \qquad \hat{u}_i = 1 - \hat{y}_i$$
  Online detection uses deterministic inference ($En' = En$), while $He$ characterizes cloud dispersion. Pairs with $\hat{u}_i < th_{pro}$ (default $0.40$) are trusted and inserted into `DetectTrie`.

### 3. Online Detection & Lazy Update

Incoming updates `(prefix, origin[, as_path])` are checked against `DetectTrie` in $O(L)$ time. Newly emerging P/O pairs are evaluated via `ModelTrie`: pairs with $\hat{u} < th_{pro}$ are accepted without alarm and lazily merged into `DetectTrie` once the pending buffer exceeds `th_update`; pairs with $\hat{u} \ge th_{pro}$ are classified via RFC 6811 `Cover`/`Match` rules into `valid`, `hijack`, `sub_hijack`, or `not_found` with per-dimension deviation diagnostics.

## CLI Reference

### `step1_build_iptrie.py`
| Argument | Description | Required |
|---|---|---|
| `--rib-file` | RIB file or directory of daily RIB snapshots | Yes |
| `--roa-dir` | RPKI ROA file or directory | No |
| `--irr-dir` | IRR file or directory | No |
| `--as-rel` | CAIDA AS relationships file or directory | No |
| `--as-org` | CAIDA AS2Org file or directory | No |
| `--window-days` | Sliding window length $d$ (default `5`) | No |
| `--end-date` | Window end date `YYYYMMDD` (defaults to latest RIB date) | No |
| `--ip-version` | `4` or `6` (default `4`) | No |
| `--bgpdump` | Path to `bgpdump` binary | No |
| `--output` | Output path for `ModelTrie` (default `./IPtrie/iptrie.dat`) | No |

### `step2_cloud_uncertainty.py`
| Argument | Description | Required |
|---|---|---|
| `--iptrie` | Path to `ModelTrie` file | Yes |
| `--output-dir` | Directory for `cloud_params.json` and `po_scores.json` | No |
| `--en-m` | Data-source gate entropy $En_m$ (default `0.15`) | No |
| `--stochastic` | Use Monte Carlo droplet simulation instead of deterministic $En'=En$ | No |
| `--n-sim` | Droplet count when `--stochastic` is enabled (default `200`) | No |
| `--seed` | Random seed when `--stochastic` is enabled (default `0`) | No |

### `step3_build_detecttrie.py`
| Argument | Description | Required |
|---|---|---|
| `--scores` | Path to `po_scores.json` | Yes |
| `--th-pro` | Uncertainty threshold $th_{pro}$ (default `0.40`) | No |
| `--threshold` | Optional confidence alias (`th_pro = 1 - threshold`) | No |
| `--output` | Output path for `DetectTrie` (default `./DetectTrie/detecttrie.dat`) | No |

### `step4_detect.py`
| Argument | Description | Required |
|---|---|---|
| `--detecttrie` | Path to `DetectTrie` file | Yes |
| `--updates` | JSON file of BGP updates (`[{prefix, origin, as_path?}, ...]`) | No |
| `--iptrie` | `ModelTrie` file for live evaluation of new pairs | No |
| `--cloud-params` | `cloud_params.json` (used with `--iptrie`) | No |
| `--th-pro` | Uncertainty threshold $th_{pro}$ (default `0.40`) | No |
| `--th-update` | Lazy update trigger count (default `100`) | No |
| `--save-updated` | Optional output path for updated `DetectTrie` | No |
| `--report` | Optional JSON path for structured anomaly reports | No |
