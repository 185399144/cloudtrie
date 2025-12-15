import os
import re
import subprocess
import ipaddress
import datetime
import chardet
from io import StringIO
from pathlib import Path
from collections import defaultdict

from iptrie import IPTrie

PANDAS_AVAILABLE = False
DATEUTIL_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except Exception as e:
    print(f"Warning: pandas import failed: {e}")

try:
    from dateutil import parser
    DATEUTIL_AVAILABLE = True
except Exception as e:
    print(f"Warning: dateutil import failed: {e}")


def normalize_asn(asn):
    return re.sub(r'^AS', '', str(asn))


def extract_date_generic(filename):
    import datetime as dt
    date_candidates = re.findall(r'\d{4}[-_]\d{1,2}[-_]\d{1,2}|\d{8}', filename)
    if date_candidates:
        for date_str in date_candidates:
            normalized_date = date_str.replace('_', '-').replace('-', '')
            try:
                if len(normalized_date) == 8:
                    year = int(normalized_date[:4])
                    month = int(normalized_date[4:6])
                    day = int(normalized_date[6:8])
                    return dt.date(year, month, day)
            except (ValueError, TypeError):
                continue
    return None


def load_ribs_to_df(fpath, bgpdump_path=None):
    try:
        if bgpdump_path is None:
            bgpdump_path = "/mnt/data/bgpd/bgpdump"
        
        res = subprocess.check_output([bgpdump_path, "-q", "-m", "-u", str(fpath)]).decode()
        fmt = "type|timestamp|A/W|peer-ip|peer-asn|prefix|as-path|origin-protocol|next-hop|local-pref|MED|community|atomic-agg|aggregator|unknown-field-1|unknown-field-2"
        cols = fmt.split("|")
        cols_needed = ["prefix", "as-path", "peer-asn"]
        col_indices = [cols.index(c) for c in cols_needed]

        rows = []
        for line in res.strip().split('\n'):
            if not line:
                continue
            parts = line.split('|')
            row = {cols_needed[i]: parts[col_indices[i]] for i in range(len(cols_needed))}
            rows.append(row)
        return rows
    except Exception as e:
        print(f"Error processing file {fpath}: {e}")
        return None


def build_trie_from_ribs(file_group, trie, bgpdump_path=None):
    total_prefixes = 0
    for files in file_group:
        for file_path in files:
            print(f"Processing RIB file: {file_path}")
            rows = load_ribs_to_df(file_path, bgpdump_path=bgpdump_path)

            if rows is None or len(rows) == 0:
                print(f"Skipping file {file_path} due to error or empty data.")
                continue

            date_from_file = extract_date_generic(file_path)

            for row in rows:
                prefix = row['prefix']
                as_path = row['as-path']
                peer_as = row['peer-asn']
                source_as = None

                if as_path and as_path != '-':
                    as_path_list = as_path.split()
                    source_as = as_path_list[-1] if as_path_list else None

                if source_as:
                    try:
                        source_as = normalize_asn(source_as)
                        ip_network = ipaddress.ip_network(prefix, strict=False)
                        if isinstance(ip_network.network_address, ipaddress.IPv4Address):
                            prefix_length = ip_network.prefixlen
                            ip_prefix = ''.join(format(int(octet), '08b') for octet in ip_network.network_address.packed)
                            ip_prefix = ip_prefix[:prefix_length]

                            announced = True
                            trie.insert(ip_prefix, source_as, 'RIB', announced, date_from_file, peer_as)
                            total_prefixes += 1

                    except ValueError:
                        pass

    print(f"Processed {len(file_group)} RIB files, total prefixes: {total_prefixes}")
    return trie


def build_trie_from_roas(file_group, trie):
    import lzma
    import csv
    
    prefix_count = 0
    for files in file_group:
        for file_path in files:
            print(f"Processing ROA file: {file_path}")

            if not isinstance(file_path, str):
                print(f"Skipping invalid file path: {file_path}")
                continue

            current_date = extract_date_generic(os.path.basename(file_path))
            if current_date is None:
                print(f"Warning: Unable to extract date from file: {file_path}")
                continue

            try:
                if str(file_path).endswith('.xz'):
                    with lzma.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            try:
                                prefix = row.get('IP Prefix') or row.get('ip_prefix')
                                source_as = row.get('ASN') or row.get('asn')
                                
                                if prefix and source_as:
                                    source_as = normalize_asn(str(source_as))
                                    ip_network = ipaddress.ip_network(prefix, strict=False)
                                    if isinstance(ip_network.network_address, ipaddress.IPv4Address):
                                        prefix_length = ip_network.prefixlen
                                        ip_prefix = ''.join(format(int(octet), '08b') for octet in ip_network.network_address.packed)
                                        ip_prefix = ip_prefix[:prefix_length]
                                        trie.insert(ip_prefix, source_as, 'RPKI', True, current_date, None)
                                        prefix_count += 1
                            except (ValueError, KeyError, AttributeError):
                                pass
                else:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            try:
                                prefix = row.get('IP Prefix') or row.get('ip_prefix')
                                source_as = row.get('ASN') or row.get('asn')
                                
                                if prefix and source_as:
                                    source_as = normalize_asn(str(source_as))
                                    ip_network = ipaddress.ip_network(prefix, strict=False)
                                    if isinstance(ip_network.network_address, ipaddress.IPv4Address):
                                        prefix_length = ip_network.prefixlen
                                        ip_prefix = ''.join(format(int(octet), '08b') for octet in ip_network.network_address.packed)
                                        ip_prefix = ip_prefix[:prefix_length]
                                        trie.insert(ip_prefix, source_as, 'RPKI', True, current_date, None)
                                        prefix_count += 1
                            except (ValueError, KeyError, AttributeError):
                                pass
            except Exception as e:
                print(f"Error reading ROA file {file_path}: {e}")
                continue

    print(f"Processed {len(file_group)} ROA files, total prefixes: {prefix_count}")
    return trie


def detect_file_encoding(file_path):
    with open(file_path, 'rb') as file:
        raw_data = file.read(1024)
    result = chardet.detect(raw_data)
    return result['encoding']


def build_trie_from_irr(folder_path, trie):
    po_pairs = set()
    route_pattern = re.compile(r'^(route6?):\s*(\S+)')
    origin_pattern = re.compile(r'origin:\s*(AS\d+)', re.IGNORECASE)

    for file_name in os.listdir(folder_path):
        file_path = os.path.join(folder_path, file_name)
        if not os.path.isfile(file_path):
            continue

        encoding = detect_file_encoding(file_path)
        print(f"Processing IRR file: {file_path}")
        try:
            with open(file_path, 'r', encoding=encoding, errors='ignore') as file:
                current_prefix = None
                for line in file:
                    line = line.strip()
                    route_match = route_pattern.match(line)
                    if route_match:
                        current_prefix = route_match.group(2)
                        continue

                    origin_match = origin_pattern.match(line)
                    if origin_match and current_prefix:
                        asn = origin_match.group(1).upper()
                        po_pairs.add((current_prefix, asn))
                        current_prefix = None
        except Exception as e:
            print(f"Error processing IRR file {file_path}: {e}")
            continue

    for prefix, asn in po_pairs:
        try:
            ip_network = ipaddress.ip_network(prefix, strict=False)
            if isinstance(ip_network, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                prefix_length = ip_network.prefixlen
                if ip_network.version == 4:
                    ip_bin = ''.join(f"{int(octet):08b}" for octet in ip_network.network_address.packed)
                else:
                    ip_bin = ''.join(f"{int(octet):08b}" for octet in ip_network.network_address.packed[:16])
                ip_bin = ip_bin[:prefix_length]
                asn = normalize_asn(asn)
                trie.insert(ip_bin, asn, 'IRR', True, None, None)
        except ValueError:
            print(f"Invalid prefix: {prefix} (ASN: {asn})")

    print(f"Processed {len(po_pairs)} P/O pairs from IRR data")
    return trie


def group_files_by_date(folder_path):
    date_to_files = defaultdict(list)

    for file in os.listdir(folder_path):
        file_date = extract_date_generic(file)
        if file_date:
            date_to_files[file_date].append(os.path.join(folder_path, file))

    sorted_dates = sorted(date_to_files.keys())
    grouped_files = []
    temp_group = []

    for i, current_date in enumerate(sorted_dates):
        if not temp_group:
            temp_group.append(current_date)
        else:
            if (current_date - temp_group[-1]).days == 1:
                temp_group.append(current_date)
            else:
                if len(temp_group) >= 5:
                    grouped_files.append([date_to_files[date] for date in temp_group])

                temp_group = [current_date]

        if len(temp_group) == 5:
            grouped_files.append([date_to_files[date] for date in temp_group])
            temp_group = []

    if len(temp_group) >= 5:
        grouped_files.append([date_to_files[date] for date in temp_group])

    return grouped_files


def build_single_trie(rib_group, roa_group, irr_folder, bgpdump_path=None):
    trie = IPTrie()
    trie = build_trie_from_roas(roa_group, trie)
    trie = build_trie_from_ribs(rib_group, trie, bgpdump_path=bgpdump_path)
    if os.path.isdir(irr_folder):
        trie = build_trie_from_irr(irr_folder, trie)
    return trie


# ============================================================
# 以下是从 build_iptrie_real.py 整合的内容
# ============================================================

import gzip


def load_single_rib_file(rib_file_path, bgpdump_path=None):
    """Load a single RIB file (handles .gz compression)"""
    if str(rib_file_path).endswith('.gz'):
        with gzip.open(rib_file_path, 'rb') as f:
            temp_path = str(rib_file_path).replace('.gz', '_temp')
            with open(temp_path, 'wb') as temp_f:
                temp_f.write(f.read())
        result = build_trie_from_ribs([[temp_path]], IPTrie(), bgpdump_path=bgpdump_path)
        os.remove(temp_path)
        return result
    else:
        return build_trie_from_ribs([[str(rib_file_path)]], IPTrie(), bgpdump_path=bgpdump_path)


def load_roa_files_from_dir(roa_dir):
    """Load all ROA files from a directory"""
    roa_files = []
    roa_dir = Path(roa_dir)
    for file_path in roa_dir.glob('roas_*.csv*'):
        roa_files.append(str(file_path))
    return sorted(roa_files)


def build_iptrie_from_real_data(rib_file=None, roa_dir=None, irr_dir=None, bgpdump_path=None):
    """
    Build IPTrie from real data sources.
    
    Args:
        rib_file: Path to a single RIB file (e.g., rrc00_updates.20170105.1200.gz)
        roa_dir: Directory containing ROA files (e.g., /mnt/data/afrinic-roa-24/)
        irr_dir: Directory containing IRR files (e.g., /mnt/data/IRR/)
        bgpdump_path: Path to bgpdump binary (default: /mnt/data/bgpd/bgpdump)
    
    Returns:
        IPTrie object
    """
    trie = IPTrie()

    if rib_file:
        print(f"Loading RIB file: {rib_file}")
        rib_file = Path(rib_file)
        if rib_file.exists():
            trie = load_single_rib_file(rib_file, bgpdump_path=bgpdump_path)
        else:
            print(f"Warning: RIB file not found: {rib_file}")

    if roa_dir:
        print(f"Loading ROA files from: {roa_dir}")
        roa_dir = Path(roa_dir)
        if roa_dir.exists():
            roa_files = load_roa_files_from_dir(roa_dir)
            if roa_files:
                roa_groups = [[f] for f in roa_files]
                trie = build_trie_from_roas(roa_groups, trie)
            else:
                print(f"Warning: No ROA files found in {roa_dir}")
        else:
            print(f"Warning: ROA directory not found: {roa_dir}")

    if irr_dir:
        print(f"Loading IRR files from: {irr_dir}")
        irr_dir = Path(irr_dir)
        if irr_dir.exists():
            trie = build_trie_from_irr(str(irr_dir), trie)
        else:
            print(f"Warning: IRR directory not found: {irr_dir}")

    return trie
