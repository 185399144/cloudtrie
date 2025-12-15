# IPTrie: Complete Workflow for BGP Prefix Hijacking Detection

A complete framework for building IPTrie from real BGP data, computing cloud model uncertainty, and detecting prefix hijacking.

## Directory Structure

```
github/
├── iptrie.py                    # Core data structure: IPTrie and TrieNode
├── cloud_uncertainty.py         # Cloud model parameter estimation and uncertainty calculation
├── detecttrie.py                # DetectTrie data structure and search interface
├── build_iptrie.py              # RIB/ROA/IRR parsing and construction functions
├── step1_build_iptrie.py        # Step 1: Build IPTrie
├── step2_cloud_uncertainty.py   # Step 2: Calculate cloud model uncertainty
├── step3_build_detecttrie.py    # Step 3: Build DetectTrie
├── step4_detect.py              # Step 4: Detection
└── README.md                    # This file
```

## Quick Start

### Complete Workflow (from raw source data)

```bash
# Step 1: Build IPTrie from source data
# Note: Add data files to the directories below
python step1_build_iptrie.py \
  --rib-file ./rib_data/ \
  --roa-dir ./roa_data/ \
  --irr-dir ./irr_data/ \
  --output ./out/iptrie.dat

# Step 2: Calculate cloud model uncertainty
python step2_cloud_uncertainty.py \
  --iptrie ./out/iptrie.dat \
  --output-dir ./out

# Step 3: Build DetectTrie
python step3_build_detecttrie.py \
  --scores ./out/po_scores.json \
  --threshold <threshold_value> \
  --output ./out/detecttrie.dat

# Step 4: Detection (requires update data)
python step4_detect.py \
  --detecttrie ./out/detecttrie.dat \
  --updates ./updates.json
```

## Data Sources

### RIB Data
- **Format**: gzip-compressed BGP update file (MRT format)
- **Location**: `./rib_data/` directory
- **Processing**: Parse using `bgpdump` tool, extract prefix, as-path, peer-asn

### ROA Data
- **Format**: CSV file with IP Prefix and ASN columns (may be .xz compressed)
- **Location**: `./roa_data/` directory
- **Processing**: Auto-decompress and read, mark as RPKI source

### IRR Data
- **Format**: RPSL format text file (route/route6 + origin fields)
- **Location**: `./irr_data/` directory
- **Processing**: Extract route and origin via regex, mark as IRR source

## Cloud Model Uncertainty Calculation

### Core Features

For each P/O pair, three features are computed:

1. **Time Persistence** (time_persistence): Exponential decay weighting
   - Uses exponential decay weights
   - Formula: weighted average

2. **Space Consistency** (space_consistency): Logarithmic transformation
   - Uses logarithmic function on peer count

3. **Source Consistency** (source_consistency): Cumulative weighting
   - Different sources have different weights
   - Formula: cumulative weight sum

### Cloud Model Parameters

For each feature, three parameters are estimated:
- **Expected Value** (Ex): mean of feature values
- **Entropy** (En): standard deviation of feature values
- **Hyper-entropy** (He): standard deviation of En estimated via bootstrap

### Uncertainty Calculation (Cloud Droplet Simulation)

Cloud droplet simulation is used to compute membership degree for each feature:
```
1. Generate n_sim cloud droplets
2. Each droplet's En' ~ N(En, He²)
3. Membership degree μ = exp(-(x - Ex)² / (2 * En'²))
4. Final membership degree = average of all droplets
```

## Parameters

### step1_build_iptrie.py

| Parameter | Description | Required |
|-----------|-------------|----------|
| `--rib-file` | RIB file path | ✓ |
| `--roa-dir` | ROA directory path | ✓ |
| `--irr-dir` | IRR directory path | ✓ |
| `--output` | Output IPTrie path | ✓ |
| `--bgpdump` | bgpdump tool path | ✗ |

### step2_cloud_uncertainty.py

| Parameter | Description | Required |
|-----------|-------------|----------|
| `--iptrie` | IPTrie file path | ✓ |
| `--output-dir` | Output directory | ✓ |
| `--n-sim` | Number of cloud droplet simulations | ✗ |
| `--seed` | Random seed | ✗ |

### step3_build_detecttrie.py

| Parameter | Description | Required |
|-----------|-------------|----------|
| `--scores` | P/O scores JSON file | ✓ |
| `--output` | Output DetectTrie path | ✓ |
| `--threshold` | Confidence threshold for P/O pair insertion | ✗ |

### step4_detect.py

| Parameter | Description | Required |
|-----------|-------------|----------|
| `--detecttrie` | DetectTrie file path | ✓ |
| `--updates` | Update data JSON file | ✗ |
