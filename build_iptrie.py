"""Data collection and preprocessing for building ModelTrie (IPTrie).

Parses:
  - BGP RIB snapshots (MRT via bgpdump or pipe-delimited bgpdump -m files)
  - RPKI ROAs (CSV / .csv.xz / TSV with maxLength for RFC 6811 validation)
  - IRR route/route6 objects (RPSL text / .gz / TSV)
  - CAIDA AS relationships (as-rel2.txt / .bz2 / .gz)
  - CAIDA AS-to-Organization mappings (as-org2info.txt.gz / .txt / TSV)
"""

import bz2
import csv
import datetime as dt
import gzip
import ipaddress
import lzma
import os
import re
import shutil
import subprocess
from pathlib import Path

try:
    import chardet
except ImportError:
    chardet = None

from iptrie import (
    DEFAULT_WINDOW_DAYS,
    IPTrie,
    clean_as_path,
    extract_org_stem,
    ip_prefix_to_bits,
    is_private_asn,
    normalize_asn,
)


def extract_date_generic(filename: str):
    """Extract YYYY-MM-DD or YYYYMMDD date from a filename, or return None."""
    name = os.path.basename(str(filename))
    candidates = re.findall(r"\d{4}[-_]\d{1,2}[-_]\d{1,2}|\d{8}", name)
    for token in candidates:
        digits = token.replace("_", "-").replace("-", "")
        if len(digits) == 8:
            try:
                return dt.date(int(digits[:4]), int(digits[4:6]), int(digits[6:8]))
            except ValueError:
                continue
    return None


def parse_date_arg(date_str):
    """Parse an explicit YYYYMMDD or YYYY-MM-DD date string into datetime.date."""
    if not date_str:
        return None
    if isinstance(date_str, dt.date):
        return date_str
    parsed = extract_date_generic(str(date_str))
    if parsed is None:
        raise ValueError(f"Invalid date format: {date_str!r} (expected YYYYMMDD or YYYY-MM-DD)")
    return parsed


def _open_text(file_path, encoding="utf-8"):
    """Open plain, .gz, .bz2, or .xz text file transparently."""
    p = str(file_path)
    if p.endswith(".gz"):
        return gzip.open(p, "rt", encoding=encoding, errors="ignore")
    if p.endswith(".bz2"):
        return bz2.open(p, "rt", encoding=encoding, errors="ignore")
    if p.endswith(".xz"):
        return lzma.open(p, "rt", encoding=encoding, errors="ignore")
    return open(p, "r", encoding=encoding, errors="ignore")


def _detect_encoding(file_path) -> str:
    p = str(file_path)
    if p.endswith((".gz", ".bz2", ".xz")) or chardet is None:
        return "utf-8"
    with open(p, "rb") as f:
        sample = f.read(2048)
    detected = chardet.detect(sample)
    return detected.get("encoding") or "utf-8"


def _resolve_bgpdump(bgpdump_path=None) -> str:
    if bgpdump_path:
        return str(bgpdump_path)
    found = shutil.which("bgpdump")
    return found if found else "bgpdump"


def _parse_network(prefix: str, ip_version: int):
    try:
        net = ipaddress.ip_network(prefix, strict=False)
        if net.version == ip_version:
            return net
    except ValueError:
        pass
    return None


def _date_from_unix_ts(ts_str: str):
    try:
        return dt.datetime.fromtimestamp(int(float(ts_str)), tz=dt.timezone.utc).date()
    except (ValueError, OverflowError, OSError):
        return None


def _extract_caida_creation_date(file_path):
    """Read CAIDA '# file creation time' header if present, else fall back to filename date."""
    try:
        with _open_text(file_path) as fh:
            for _ in range(25):
                line = fh.readline()
                if not line or not line.startswith("#"):
                    break
                if "file creation time" in line.lower():
                    m = re.search(r"(\d{4}-\d{2}-\d{2}|\d{8})", line)
                    if m:
                        d = extract_date_generic(m.group(1))
                        if d is not None:
                            return d
    except Exception:
        pass
    return extract_date_generic(file_path)


def _select_window_rib_files(files, end_date=None, window_days: int = DEFAULT_WINDOW_DAYS):
    """Select RIB files belonging to the d-day window ending at end_date."""
    dated = [(f, extract_date_generic(f)) for f in files]
    available_dates = [d for _, d in dated if d is not None]
    if not available_dates:
        return files, end_date

    target_end = end_date if end_date is not None else max(available_dates)
    start_date = target_end - dt.timedelta(days=max(int(window_days), 1) - 1)
    selected = [f for f, d in dated if d is None or (start_date <= d <= target_end)]
    return selected, target_end


def _select_snapshot_files(files, end_date=None, check_caida_header: bool = False):
    """When multiple dated snapshots exist in a directory, select the latest date <= end_date."""
    if end_date is None or len(files) <= 1:
        return files
    dated = []
    undated = []
    for f in files:
        d = _extract_caida_creation_date(f) if check_caida_header else extract_date_generic(f)
        if d is None:
            undated.append(f)
        else:
            dated.append((f, d))
    if not dated:
        return files
    eligible = [(f, d) for f, d in dated if d <= end_date]
    if not eligible:
        return undated
    latest = max(d for _, d in eligible)
    return undated + [f for f, d in eligible if d == latest]


def iter_rib_records(fpath, bgpdump_path=None):
    """Stream (timestamp_str, prefix, as_path, peer_asn) tuples from a RIB snapshot."""
    path_str = str(fpath)
    if path_str.endswith((".txt", ".tsv", ".dump", ".csv")):
        with _open_text(path_str) as fh:
            for line in fh:
                parts = line.rstrip("\n").split("|")
                if len(parts) >= 7:
                    yield parts[1], parts[5], parts[6], parts[4]
        return

    bgpdump = _resolve_bgpdump(bgpdump_path)
    proc = subprocess.Popen(
        [bgpdump, "-q", "-m", "-u", path_str],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="ignore",
    )
    assert proc.stdout is not None
    try:
        for line in proc.stdout:
            parts = line.rstrip("\n").split("|")
            if len(parts) >= 7:
                yield parts[1], parts[5], parts[6], parts[4]
    finally:
        proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        rc = proc.wait()
        if rc != 0:
            raise RuntimeError(f"bgpdump exited with code {rc} on {path_str}")


def build_trie_from_ribs(rib_files, trie: IPTrie, bgpdump_path=None, ip_version: int = 4):
    """Parse one or more RIB files into ModelTrie with AS-path cleaning."""
    total_records = 0
    for fpath in rib_files:
        fpath_str = str(fpath)
        print(f"Processing RIB file: {fpath_str}")
        file_date = extract_date_generic(fpath_str)
        try:
            for ts_str, prefix, as_path, peer_as in iter_rib_records(
                fpath_str, bgpdump_path=bgpdump_path
            ):
                net = _parse_network(prefix, ip_version)
                if net is None or net.prefixlen < trie.min_prefix_len:
                    continue
                paths = clean_as_path(as_path)
                if not paths:
                    continue
                rec_date = file_date if file_date is not None else _date_from_unix_ts(ts_str)
                prefix_bits = ip_prefix_to_bits(prefix)
                for path in paths:
                    origin = path[-1]
                    upstream = path[-2] if len(path) >= 2 else None
                    trie.insert(
                        prefix_bits,
                        origin,
                        "RIB",
                        announced=True,
                        date=rec_date,
                        peer_as=peer_as,
                        upstream_as=upstream,
                    )
                    total_records += 1
        except Exception as exc:
            print(f"Warning: failed to process RIB file {fpath_str}: {exc}")
    print(f"Processed {len(rib_files)} RIB file(s), total cleaned records: {total_records}")
    return trie


def build_trie_from_roas(roa_files, trie: IPTrie, ip_version: int = 4):
    """Parse RPKI ROA CSV / .csv.xz / TSV files into ModelTrie (preserving maxLength)."""
    roa_count = 0
    for fpath in roa_files:
        fpath_str = str(fpath)
        print(f"Processing ROA file: {fpath_str}")
        try:
            with _open_text(fpath_str) as fh:
                first_line = fh.readline()
                if not first_line:
                    continue
                fh.seek(0)
                if "\t" in first_line and "," not in first_line:
                    for line in fh:
                        parts = line.strip().split("\t")
                        if len(parts) < 3:
                            continue
                        prefix, ml_str, asn_str = parts[0], parts[1], parts[2]
                        net = _parse_network(prefix, ip_version)
                        if net is None:
                            continue
                        try:
                            asn = normalize_asn(asn_str)
                            ml = int(ml_str) if ml_str else net.prefixlen
                            trie.insert(ip_prefix_to_bits(prefix), asn, "RPKI", True, max_length=ml)
                            roa_count += 1
                        except ValueError:
                            continue
                else:
                    reader = csv.DictReader(fh)
                    for row in reader:
                        prefix = (
                            row.get("IP Prefix")
                            or row.get("ip_prefix")
                            or row.get("Prefix")
                            or row.get("prefix")
                        )
                        asn_str = row.get("ASN") or row.get("asn")
                        ml_str = (
                            row.get("Max Length")
                            or row.get("max_length")
                            or row.get("MaxLength")
                            or row.get("maxlen")
                        )
                        if not prefix or not asn_str:
                            continue
                        net = _parse_network(prefix, ip_version)
                        if net is None:
                            continue
                        try:
                            asn = normalize_asn(asn_str)
                            ml = int(ml_str) if (ml_str and str(ml_str).strip()) else net.prefixlen
                            trie.insert(ip_prefix_to_bits(prefix), asn, "RPKI", True, max_length=ml)
                            roa_count += 1
                        except ValueError:
                            continue
        except Exception as exc:
            print(f"Warning: failed to read ROA file {fpath_str}: {exc}")
    print(f"Processed {len(roa_files)} ROA file(s), total ROAs: {roa_count}")
    return trie


def build_trie_from_irr(irr_files, trie: IPTrie, ip_version: int = 4):
    """Parse IRR RPSL (route/route6 + origin) or TSV files into ModelTrie."""
    route_re = re.compile(r"^(route6?):\s*(\S+)", re.IGNORECASE)
    origin_re = re.compile(r"^origin:\s*(AS\d+)", re.IGNORECASE)
    po_pairs = set()

    if isinstance(irr_files, (str, Path)):
        p = Path(irr_files)
        files = [str(p)] if p.is_file() else _collect_files(p)
    else:
        files = list(irr_files)

    for fpath in files:
        print(f"Processing IRR file: {fpath}")
        enc = _detect_encoding(fpath)
        try:
            with _open_text(fpath, encoding=enc) as fh:
                current_prefix = None
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line:
                        current_prefix = None
                        continue
                    if "\t" in line and not line.lower().startswith(("route", "origin")):
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            po_pairs.add((parts[0].strip(), parts[1].strip()))
                        continue
                    rm = route_re.match(line)
                    if rm:
                        current_prefix = rm.group(2)
                        continue
                    om = origin_re.match(line)
                    if om and current_prefix:
                        po_pairs.add((current_prefix, om.group(1)))
                        current_prefix = None
        except Exception as exc:
            print(f"Warning: failed to process IRR file {fpath}: {exc}")

    inserted = 0
    for prefix, asn_str in po_pairs:
        net = _parse_network(prefix, ip_version)
        if net is None or net.prefixlen < trie.min_prefix_len:
            continue
        try:
            asn = normalize_asn(asn_str)
            if is_private_asn(asn):
                continue
            trie.insert(ip_prefix_to_bits(prefix), asn, "IRR", True)
            inserted += 1
        except ValueError:
            continue

    print(f"Processed {inserted} IRR P/O pairs from {len(files)} file(s)")
    return trie


def load_as_relationships(path, end_date=None):
    """Load CAIDA AS relationships (a|b|-1 for provider->customer, a|b|0 for peer)."""
    prov = set()
    peer = set()
    files = _select_snapshot_files(_collect_files(path), end_date=end_date)
    for fpath in files:
        print(f"Loading AS relationships: {fpath}")
        with _open_text(fpath) as fh:
            for line in fh:
                if not line or line.startswith("#"):
                    continue
                parts = line.strip().split("|")
                if len(parts) < 3:
                    continue
                try:
                    a, b, rel = int(parts[0]), int(parts[1]), int(parts[2])
                except ValueError:
                    continue
                if rel == -1:
                    prov.add((a, b))
                else:
                    peer.add((a, b))
                    peer.add((b, a))
    print(f"Loaded AS relationships: {len(prov)} p2c edges, {len(peer) // 2} p2p edges")
    return {"prov": prov, "peer": peer}


def load_as_organizations(path, end_date=None):
    """Load CAIDA as-org2info (.txt / .txt.gz) or mapped TSV (asn\\torg_id\\tstem)."""
    org = {}
    oname = {}
    stem = {}
    files = _select_snapshot_files(
        _collect_files(path), end_date=end_date, check_caida_header=True
    )

    for fpath in files:
        print(f"Loading AS organizations: {fpath}")
        mode = None
        with _open_text(fpath) as fh:
            for line in fh:
                if line.startswith("# format:aut"):
                    mode = "aut"
                    continue
                if line.startswith("# format:org"):
                    mode = "org"
                    continue
                if line.startswith("#") or not line.strip():
                    continue
                if "|" in line:
                    parts = line.strip().split("|")
                    if mode == "aut" and len(parts) >= 4:
                        try:
                            org[int(parts[0])] = parts[3]
                        except ValueError:
                            continue
                    elif mode == "org" and len(parts) >= 3:
                        oname[parts[0]] = parts[2]
                elif "\t" in line:
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        try:
                            asn = int(parts[0])
                        except ValueError:
                            continue
                        if parts[1] and parts[1] != "0":
                            org[asn] = parts[1]
                        if len(parts) >= 3 and parts[2] and parts[2] != "0":
                            stem[asn] = parts[2]

    for asn, oid in org.items():
        if asn not in stem and oid in oname:
            st = extract_org_stem(oname[oid])
            if st:
                stem[asn] = st

    print(f"Loaded AS organizations: {len(org)} AS-org mappings, {len(stem)} name stems")
    return {"org": org, "stem": stem}


def _collect_files(path_or_dir, patterns=None):
    """Return sorted list of non-hidden files from a file path or directory."""
    p = Path(path_or_dir)
    if not p.exists():
        return []
    if p.is_file():
        return [str(p)]
    files = []
    if patterns:
        for pat in patterns:
            files.extend(str(f) for f in p.glob(pat) if f.is_file())
    if not files:
        files = [str(f) for f in p.iterdir() if f.is_file() and not f.name.startswith(".")]
    return sorted(set(files))


def build_iptrie_from_real_data(
    rib_file=None,
    roa_dir=None,
    irr_dir=None,
    as_rel_path=None,
    as_org_path=None,
    bgpdump_path=None,
    window_days: int = DEFAULT_WINDOW_DAYS,
    end_date=None,
    ip_version: int = 4,
):
    """Build ModelTrie (IPTrie) from BGP RIB, RPKI ROA, IRR, AS-rel, and AS2Org sources."""
    trie = IPTrie(window_days=window_days, ip_version=ip_version)
    target_end = parse_date_arg(end_date)

    rib_files = []
    if rib_file:
        all_ribs = _collect_files(rib_file)
        if all_ribs:
            rib_files, target_end = _select_window_rib_files(
                all_ribs, end_date=target_end, window_days=window_days
            )
        else:
            print(f"Warning: No RIB files found at: {rib_file}")

    if as_rel_path and Path(as_rel_path).exists():
        trie.set_as_relationships(load_as_relationships(as_rel_path, end_date=target_end))
    elif as_rel_path:
        print(f"Warning: AS relationship path not found: {as_rel_path}")

    if as_org_path and Path(as_org_path).exists():
        trie.set_as_organizations(load_as_organizations(as_org_path, end_date=target_end))
    elif as_org_path:
        print(f"Warning: AS organization path not found: {as_org_path}")

    if rib_files:
        trie = build_trie_from_ribs(
            rib_files, trie, bgpdump_path=bgpdump_path, ip_version=ip_version
        )

    if roa_dir:
        roa_files = _collect_files(roa_dir, patterns=("*.csv", "*.csv.xz", "*.tsv"))
        roa_files = _select_snapshot_files(roa_files, end_date=target_end)
        if roa_files:
            trie = build_trie_from_roas(roa_files, trie, ip_version=ip_version)
        else:
            print(f"Warning: No ROA files found at: {roa_dir}")

    if irr_dir:
        irr_files = _collect_files(irr_dir)
        irr_files = _select_snapshot_files(irr_files, end_date=target_end)
        if irr_files:
            trie = build_trie_from_irr(irr_files, trie, ip_version=ip_version)
        else:
            print(f"Warning: No IRR files found at: {irr_dir}")

    return trie
