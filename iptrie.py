"""Core ModelTrie (IPTrie) data structure and P/O feature extraction for CloudTrie.

Implements the normalized [0, 1] spatio-temporal and data-source features:
  - Temporal persistence (s^t): normalized recency-weighted presence over a d-day window.
  - Spatial consistency (s^r): min(max_c rho(o, c), 1 - Q(o) / N(o)) using competing
    origins, AS business relationships, AS organizations, and origin consistency counters.
  - Data source reliability (s^m): RFC 6811 RPKI validation + IRR corroboration mapped
    to [0, 1], with RPKI-invalid suppressing unverified IRR records.
"""

import datetime
import ipaddress
import pickle
import re
from collections import defaultdict
from pathlib import Path


DEFAULT_WINDOW_DAYS = 5
DEFAULT_MIN_PREFIX_LEN = 8
DEFAULT_SOURCE_WEIGHTS = (0.9, 0.7)  # (RPKI weight omega_1, IRR weight omega_2)

_ORG_STOPWORDS = frozenset({
    "china", "national", "internet", "network", "networks", "telecom",
    "telecommunications", "telecommunication", "communications", "communication",
    "global", "data", "cable", "digital", "services", "service", "systems",
    "system", "solutions", "university", "college", "institute", "company",
    "limited", "corporation", "group", "international", "technologies",
    "technology", "online", "broadband", "wireless", "mobile", "telecomunicacoes",
    "telecomunicaciones", "comunicacoes", "servicos", "provedor", "the", "and",
    "of", "de", "do", "da", "del", "la", "le", "les", "net", "web", "host",
    "hosting", "cloud", "server", "servers", "datacenter", "center", "centre",
    "info", "information", "micro", "media", "first", "new", "north", "south",
    "east", "west", "american", "united", "state", "city", "county", "government",
    "ministry", "department", "public", "private",
})


def is_private_asn(asn: int) -> bool:
    """Return True if ASN is reserved/private or invalid for public BGP routing."""
    return (
        asn <= 0
        or asn == 23456
        or (64512 <= asn <= 65534)
        or (4200000000 <= asn <= 4294967294)
        or asn > 0xFFFFFFFF
    )


def normalize_asn(asn) -> int:
    """Normalize an ASN string or integer (e.g. 'AS15169' -> 15169)."""
    if isinstance(asn, int):
        return asn
    s = str(asn).strip().upper()
    if s.startswith("AS"):
        s = s[2:]
    return int(s)


def clean_as_path(as_path: str):
    """Clean a raw BGP AS_PATH string and decompose aggregated AS_SETs.

    Steps:
      1. Decompose aggregated AS_SET segments '{a,b}' into separate paths.
      2. Remove private/reserved ASNs.
      3. Collapse consecutive duplicate ASNs (AS path prepending).

    Returns:
      List of cleaned AS paths (each a non-empty list of ints).
    """
    if not as_path or as_path == "-":
        return []

    raw_tokens = as_path.strip().split()
    expanded = [[]]
    for tok in raw_tokens:
        if tok.startswith("{") and tok.endswith("}"):
            members = []
            for part in re.split(r"[,;\s]+", tok[1:-1].strip()):
                if not part:
                    continue
                try:
                    val = normalize_asn(part)
                    if not is_private_asn(val):
                        members.append(val)
                except ValueError:
                    continue
            if not members:
                continue
            # Cap combinatorial blowup for pathological AS_SETs while keeping every origin member.
            if len(expanded) * len(members) > 64:
                members = members[:1]
            expanded = [p + [m] for p in expanded for m in members]
        else:
            try:
                val = normalize_asn(tok)
            except ValueError:
                continue
            if is_private_asn(val):
                continue
            for p in expanded:
                p.append(val)

    cleaned = []
    seen = set()
    for path in expanded:
        dedup = []
        for asn in path:
            if not dedup or dedup[-1] != asn:
                dedup.append(asn)
        if dedup:
            key = tuple(dedup)
            if key not in seen:
                seen.add(key)
                cleaned.append(dedup)
    return cleaned


def extract_org_stem(org_name: str):
    """Extract a distinctive organization name stem for sister-AS matching."""
    if not org_name:
        return None
    for tok in re.findall(r"[a-z0-9]+", org_name.lower()):
        if len(tok) >= 5 and tok not in _ORG_STOPWORDS and not tok.isdigit():
            return tok
    return None


def ip_prefix_to_bits(prefix: str) -> str:
    """Convert CIDR prefix (IPv4 or IPv6) to its binary bitstring."""
    net = ipaddress.ip_network(prefix, strict=False)
    bitlen = net.max_prefixlen
    addr_int = int(net.network_address)
    return format(addr_int, f"0{bitlen}b")[: net.prefixlen]


def bits_to_ip_prefix(prefix_bits: str, ip_version: int = 4) -> str:
    """Convert a binary prefix bitstring back to standard CIDR notation."""
    bitlen = 32 if ip_version == 4 else 128
    plen = len(prefix_bits)
    addr_int = int(prefix_bits.ljust(bitlen, "0"), 2) if plen > 0 else 0
    addr = ipaddress.IPv4Address(addr_int) if ip_version == 4 else ipaddress.IPv6Address(addr_int)
    return f"{addr}/{plen}"


def default_temporal_weights(window_days: int = DEFAULT_WINDOW_DAYS):
    """Recency weights w_t (newest day first), e.g., [1.0, 0.8, 0.6, 0.4, 0.2] for d=5."""
    d = max(int(window_days), 1)
    return [(d - j) / float(d) for j in range(d)]


class TrieNode:
    """Node in ModelTrie (IPTrie) storing per-prefix BGP, RPKI, and IRR evidence."""

    __slots__ = (
        "children",
        "is_end_of_prefix",
        "rib_dates",
        "rib_peers",
        "rib_upstreams",
        "roa_records",
        "irr_origins",
        "sources",
    )

    def __init__(self):
        self.children = {"0": None, "1": None}
        self.is_end_of_prefix = False
        # origin_asn -> set of datetime.date (or int day indices) observed in BGP RIB
        self.rib_dates = defaultdict(set)
        # origin_asn -> set of peer ASNs observing this (prefix, origin)
        self.rib_peers = defaultdict(set)
        # origin_asn -> set of direct upstream / transit ASNs on observed BGP paths
        self.rib_upstreams = defaultdict(set)
        # set of (origin_asn, max_length) from RPKI ROAs
        self.roa_records = set()
        # set of origin_asn from IRR route/route6 objects
        self.irr_origins = set()
        # origin_asn -> set of data source tags ('RIB', 'RPKI', 'IRR')
        self.sources = defaultdict(set)


class IPTrie:
    """ModelTrie storing multi-source prefix/origin observations and AS context."""

    def __init__(
        self,
        window_days: int = DEFAULT_WINDOW_DAYS,
        as_relationships=None,
        as_organizations=None,
        min_prefix_len: int = DEFAULT_MIN_PREFIX_LEN,
        ip_version: int = 4,
    ):
        self.root = TrieNode()
        self.window_days = int(window_days)
        self.min_prefix_len = int(min_prefix_len)
        self.ip_version = int(ip_version)

        # Business relationships: prov_pairs contains (provider, customer),
        # peer_pairs contains symmetric (a, b) & (b, a).
        self.prov_pairs = set()
        self.peer_pairs = set()
        self.prov_adj = defaultdict(set)  # customer -> set of providers
        if as_relationships:
            self.set_as_relationships(as_relationships)

        # AS organizations: as_org[asn] = org_id, as_stem[asn] = name_stem
        self.as_org = {}
        self.as_stem = {}
        if as_organizations:
            self.set_as_organizations(as_organizations)

        # Observed BGP link history: (upstream_asn, origin_asn)
        self.link_history = set()
        # Observed RIB dates (for automatic newest-first window alignment)
        self.observed_dates = set()

        # Cached state populated during collect_po_pairs() for fast online evaluation
        self.origin_n_pfx = defaultdict(int)   # N(o): active BGP prefixes of origin o
        self.origin_q_pfx = defaultdict(int)   # Q(o): unrelated conflicting prefixes of o
        self.space_set = set()                 # (ancestor_bits, origin_asn) delegation cache
        self._ancestor_cache = {}
        self._rib_pair_hbits = {}              # (prefix_bits, origin_asn) -> bitmask over d days
        self._online_seen_new = set()          # new (prefix_bits, origin_asn) counted online

    def set_as_relationships(self, relationships):
        """Load provider-customer and peer-to-peer relationships.

        Accepts either a dict {'prov': set, 'peer': set} or an iterable of
        (asn_a, asn_b, rel) tuples where rel == -1 (provider->customer) or 0 (peer).
        """
        if isinstance(relationships, dict):
            for p, c in relationships.get("prov", ()):
                p, c = int(p), int(c)
                self.prov_pairs.add((p, c))
                self.prov_adj[c].add(p)
            for a, b in relationships.get("peer", ()):
                a, b = int(a), int(b)
                self.peer_pairs.add((a, b))
                self.peer_pairs.add((b, a))
        else:
            for a, b, rel in relationships:
                a, b, rel = int(a), int(b), int(rel)
                if rel == -1:
                    self.prov_pairs.add((a, b))
                    self.prov_adj[b].add(a)
                else:
                    self.peer_pairs.add((a, b))
                    self.peer_pairs.add((b, a))
        self._ancestor_cache.clear()

    def set_as_organizations(self, organizations):
        """Load AS-to-organization mappings.

        Accepts either {'org': {asn: org_id}, 'stem': {asn: stem}} or {asn: (org_id, org_name_or_stem)}.
        """
        if isinstance(organizations, dict) and "org" in organizations:
            self.as_org.update({int(k): v for k, v in organizations["org"].items() if v})
            self.as_stem.update({int(k): v for k, v in organizations.get("stem", {}).items() if v})
        elif isinstance(organizations, dict):
            for asn, val in organizations.items():
                asn_i = int(asn)
                if isinstance(val, (tuple, list)) and len(val) >= 2:
                    oid, name_or_stem = val[0], val[1]
                    if oid:
                        self.as_org[asn_i] = oid
                    if name_or_stem:
                        self.as_stem[asn_i] = extract_org_stem(str(name_or_stem)) or str(name_or_stem)
                elif val:
                    self.as_org[asn_i] = val

    def _walk_create(self, prefix_bits: str) -> TrieNode:
        node = self.root
        for bit in prefix_bits:
            nxt = node.children[bit]
            if nxt is None:
                nxt = TrieNode()
                node.children[bit] = nxt
            node = nxt
        node.is_end_of_prefix = True
        return node

    def _walk_covering(self, prefix_bits: str):
        """Yield (depth, sub_bits, node) for all existing nodes along prefix_bits."""
        node = self.root
        for depth, bit in enumerate(prefix_bits, start=1):
            node = node.children.get(bit)
            if node is None:
                break
            yield depth, prefix_bits[:depth], node

    def insert(
        self,
        ip_prefix: str,
        source_as,
        source: str,
        announced: bool = True,
        date=None,
        peer_as=None,
        max_length=None,
        upstream_as=None,
    ):
        """Insert a P/O observation from RIB, RPKI, or IRR into ModelTrie.

        Args:
            ip_prefix: Binary prefix string (e.g. '11000000...') or CIDR string.
            source_as: Origin ASN (int or 'AS...').
            source: 'RIB', 'RPKI', or 'IRR'.
            announced: Whether the route is announced (False entries are ignored).
            date: datetime.date (or int day index) for RIB observations.
            peer_as: Observing vantage-point peer ASN (optional).
            max_length: RPKI ROA maxLength (defaults to len(prefix_bits)).
            upstream_as: Immediate upstream ASN (or iterable of ASNs on AS_PATH) for RIB.
        """
        if not announced:
            return
        prefix_bits = ip_prefix_to_bits(ip_prefix) if ("/" in ip_prefix) else ip_prefix
        origin = normalize_asn(source_as)
        src = str(source).upper()

        node = self._walk_create(prefix_bits)
        if src == "RIB":
            if origin <= 0:
                return
            node.sources[origin].add("RIB")
            if date is not None:
                node.rib_dates[origin].add(date)
                self.observed_dates.add(date)
            else:
                node.rib_dates[origin].add(0)
            if peer_as is not None and str(peer_as).strip() != "":
                try:
                    node.rib_peers[origin].add(normalize_asn(peer_as))
                except ValueError:
                    pass
            if upstream_as is not None:
                ups = [upstream_as] if isinstance(upstream_as, (int, str)) else upstream_as
                for u in ups:
                    try:
                        u_int = normalize_asn(u)
                    except ValueError:
                        continue
                    if not is_private_asn(u_int) and u_int != origin:
                        node.rib_upstreams[origin].add(u_int)
                        self.link_history.add((u_int, origin))
        elif src == "RPKI":
            ml = int(max_length) if max_length is not None else len(prefix_bits)
            node.roa_records.add((origin, ml))
            if origin > 0:
                node.sources[origin].add("RPKI")
        elif src == "IRR":
            if origin <= 0:
                return
            node.irr_origins.add(origin)
            node.sources[origin].add("IRR")
        else:
            if origin > 0:
                node.sources[origin].add(src)

    def search(self, ip_prefix: str):
        """Exact-match lookup returning (sources, rib_peers) or None."""
        prefix_bits = ip_prefix_to_bits(ip_prefix) if ("/" in ip_prefix) else ip_prefix
        node = self.root
        for bit in prefix_bits:
            node = node.children.get(bit)
            if node is None:
                return None
        if node.is_end_of_prefix:
            return node.sources, node.rib_peers
        return None

    def save_to_file(self, file_path):
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("wb") as f:
            pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)

    @staticmethod
    def load_from_file(file_path):
        with Path(file_path).open("rb") as f:
            return pickle.load(f)

    def iter_prefix_nodes(self):
        """Iterative DFS returning all (prefix_bits, node) pairs with is_end_of_prefix."""
        out = []
        stack = [("", self.root)]
        while stack:
            bits, node = stack.pop()
            if node.is_end_of_prefix:
                out.append((bits, node))
            c1 = node.children["1"]
            c0 = node.children["0"]
            if c1 is not None:
                stack.append((bits + "1", c1))
            if c0 is not None:
                stack.append((bits + "0", c0))
        return out

    def _ref_origins_at(self, node: TrieNode):
        """Reference origins at a node: BGP RIB origins union non-zero RPKI ROA origins."""
        refs = set(node.rib_dates.keys())
        for roa_asn, _ in node.roa_records:
            if roa_asn > 0:
                refs.add(roa_asn)
        return refs

    def _get_ancestors(self, asn: int, max_nodes: int = 500):
        """Provider-cone ancestors of asn (memoized)."""
        cached = self._ancestor_cache.get(asn)
        if cached is not None:
            return cached
        seen = set()
        stack = [asn]
        while stack and len(seen) < max_nodes:
            cur = stack.pop()
            for prov in self.prov_adj.get(cur, ()):
                if prov not in seen:
                    seen.add(prov)
                    if len(seen) < max_nodes:
                        stack.append(prov)
        self._ancestor_cache[asn] = seen
        return seen

    def _relationship_score(self, origin: int, comp: int, ups_origin, space_hit: bool) -> float:
        """Compute graded relationship closeness rho(o, c) in [0, 1]."""
        org_o = self.as_org.get(origin)
        if org_o is not None and org_o == self.as_org.get(comp):
            return 1.0
        stem_o = self.as_stem.get(origin)
        if stem_o is not None and stem_o == self.as_stem.get(comp):
            return 0.9
        if space_hit:
            return 0.9
        if (origin, comp) in self.prov_pairs or (comp, origin) in self.prov_pairs:
            return 0.9
        if comp in ups_origin:
            return 0.9
        if comp in self._get_ancestors(origin) or origin in self._get_ancestors(comp):
            return 0.7
        if (origin, comp) in self.link_history or (comp, origin) in self.link_history:
            return 0.3 if (origin, comp) in self.peer_pairs else 0.6
        if (origin, comp) in self.peer_pairs:
            return 0.3
        return 0.0

    def _rpki_irr_and_competitors(self, prefix_bits: str, origin: int):
        """Evaluate RFC 6811 RPKI status, IRR presence, and covering competing origins."""
        plen = len(prefix_bits)
        roa_covered = False
        roa_valid = False
        irr_valid = False
        comp_space = {}  # comp_asn -> bool (whether origin has SPACE hit at that covering node)

        for depth, sub_bits, node in self._walk_covering(prefix_bits):
            if node.roa_records:
                roa_covered = True
                for roa_asn, ml in node.roa_records:
                    if roa_asn == origin and ml >= plen:
                        roa_valid = True
            if depth >= self.min_prefix_len and node.irr_origins:
                if origin in node.irr_origins:
                    irr_valid = True
            if depth >= self.min_prefix_len:
                refs = self._ref_origins_at(node)
                if refs:
                    sp_hit = (sub_bits, origin) in self.space_set
                    for c in refs:
                        if c == origin:
                            continue
                        comp_space[c] = comp_space.get(c, False) or sp_hit

        k1 = 1 if roa_valid else (-1 if roa_covered else 0)
        k2 = 0 if k1 == -1 else (1 if irr_valid else 0)
        return k1, k2, comp_space

    def _compute_hbits(self, dates_set, latest_date, window_days: int) -> int:
        """Build d-bit persistence bitmask (bit 0 = newest day, bit d-1 = oldest day)."""
        if not dates_set:
            return 0
        hbits = 0
        for d in dates_set:
            if isinstance(d, datetime.date) and isinstance(latest_date, datetime.date):
                offset = (latest_date - d).days
            elif isinstance(d, int):
                offset = d
            else:
                offset = 0
            if 0 <= offset < window_days:
                hbits |= 1 << offset
        return hbits

    def _build_space_and_origin_counts(self, prefix_nodes):
        """Populate space_set (delegation evidence) and N(o) over active BGP pairs."""
        self.space_set.clear()
        self.origin_n_pfx.clear()
        self.origin_q_pfx.clear()

        for prefix_bits, node in prefix_nodes:
            plen = len(prefix_bits)
            if not node.rib_dates:
                continue
            for origin in node.rib_dates:
                self.origin_n_pfx[origin] += 1
                # Mark strictly shorter covering ancestors that have any ref origin != origin
                for depth, sub_bits, anc_node in self._walk_covering(prefix_bits):
                    if depth < self.min_prefix_len or depth >= plen:
                        continue
                    refs = self._ref_origins_at(anc_node)
                    if refs and (len(refs) > 1 or origin not in refs):
                        self.space_set.add((sub_bits, origin))

    def collect_po_pairs(self, source_weights=DEFAULT_SOURCE_WEIGHTS):
        """Extract normalized [0, 1] features (s^t, s^r, s^m) for every P/O pair in ModelTrie."""
        prefix_nodes = self.iter_prefix_nodes()
        self._build_space_and_origin_counts(prefix_nodes)

        real_dates = [d for d in self.observed_dates if isinstance(d, datetime.date)]
        latest_date = max(real_dates) if real_dates else None
        w_t = default_temporal_weights(self.window_days)
        w_t_sum = sum(w_t)
        w1, w2 = float(source_weights[0]), float(source_weights[1])
        full_mask = (1 << self.window_days) - 1

        self._rib_pair_hbits.clear()
        self._online_seen_new.clear()

        # Pass 1: compute s^t, s^m, competing-origin score rho, and accumulate Q(o).
        intermediate = []
        for prefix_bits, node in prefix_nodes:
            all_origins = set(node.sources.keys()) | set(node.rib_dates.keys()) | set(node.irr_origins)
            for roa_asn, _ in node.roa_records:
                if roa_asn > 0:
                    all_origins.add(roa_asn)

            for origin in sorted(all_origins):
                has_rib = origin in node.rib_dates and len(node.rib_dates[origin]) > 0
                hbits = self._compute_hbits(node.rib_dates.get(origin), latest_date, self.window_days) if has_rib else 0
                if has_rib:
                    self._rib_pair_hbits[(prefix_bits, origin)] = hbits

                # Temporal persistence s^t in [0, 1] (Eq. 2)
                h_vec = [(hbits >> j) & 1 for j in range(self.window_days)]
                s_t = sum(h * w for h, w in zip(h_vec, w_t)) / w_t_sum

                # RPKI / IRR validation & competing origins
                k1, k2, comp_space = self._rpki_irr_and_competitors(prefix_bits, origin)
                has_comp = bool(comp_space)

                # Data source score s^m in [0, 1] (Eq. 4)
                s_m = 0.5 + (w1 * k1 + w2 * k2) / (2.0 * (w1 + w2))

                # Relationship closeness max_c rho(o, c)
                ups_o = node.rib_upstreams.get(origin, ())
                if not comp_space:
                    best_rho = 1.0
                else:
                    best_rho = 0.0
                    for comp_asn, sp_hit in comp_space.items():
                        r_val = self._relationship_score(origin, comp_asn, ups_o, sp_hit)
                        if r_val > best_rho:
                            best_rho = r_val
                            if best_rho >= 1.0:
                                break

                rho_eff = 1.0 if k1 == 1 else best_rho
                is_unrelated = bool(has_rib and has_comp and rho_eff == 0.0)
                if is_unrelated:
                    self.origin_q_pfx[origin] += 1

                sources = set(node.sources.get(origin, ()))
                if has_rib:
                    sources.add("RIB")
                if k1 == 1:
                    sources.add("RPKI")
                if origin in node.irr_origins:
                    sources.add("IRR")

                intermediate.append((
                    prefix_bits,
                    origin,
                    sorted(sources),
                    has_rib,
                    len(node.rib_peers.get(origin, ())),
                    h_vec,
                    hbits,
                    hbits == full_mask,
                    has_comp,
                    k1,
                    k2,
                    s_t,
                    rho_eff,
                    s_m,
                    is_unrelated,
                ))

        # Pass 2: finalize origin consistency O(o) = 1 - Q(o)/N(o) and s^r (Eq. 3).
        po_list = []
        for (
            prefix_bits,
            origin,
            sources,
            has_rib,
            peer_count,
            h_vec,
            hbits,
            full_window,
            has_comp,
            k1,
            k2,
            s_t,
            rho_eff,
            s_m,
            is_unrelated,
        ) in intermediate:
            n_o = self.origin_n_pfx.get(origin, 0)
            q_o = self.origin_q_pfx.get(origin, 0)
            o_score = (1.0 - q_o / float(n_o)) if n_o > 0 else (0.0 if is_unrelated else 1.0)
            s_r = min(rho_eff, o_score) if has_rib else 0.0

            po_list.append({
                "prefix": bits_to_ip_prefix(prefix_bits, self.ip_version),
                "prefix_bits": prefix_bits,
                "origin": int(origin),
                "sources": sources,
                "has_rib": bool(has_rib),
                "has_comp": bool(has_comp),
                "full_window": bool(full_window),
                "hbits": int(hbits),
                "peer_count": int(peer_count),
                "rpki_status": int(k1),
                "irr_status": int(k2),
                "time_vectors": h_vec,
                "time_persistence": float(s_t),
                "space_consistency": float(s_r),
                "source_consistency": float(s_m),
                "relation_score": float(rho_eff),
                "origin_consistency": float(o_score),
            })

        return po_list

    def evaluate_live_pair(
        self,
        prefix: str,
        origin_asn,
        as_path=None,
        source_weights=DEFAULT_SOURCE_WEIGHTS,
        update_counters: bool = True,
    ):
        """Compute live normalized features (s^t, s^r, s^m) for an online BGP announcement.

        Used during Step 4 online detection to score newly arriving P/O pairs against
        ModelTrie and update origin-level counters N(o) and Q(o) on first sight.
        """
        prefix_bits = ip_prefix_to_bits(prefix) if ("/" in prefix) else prefix
        origin = normalize_asn(origin_asn)
        w_t = default_temporal_weights(self.window_days)
        w_t_sum = sum(w_t)
        w1, w2 = float(source_weights[0]), float(source_weights[1])

        # Rolling d-day persistence: live announcement fills newest slot (bit 0);
        # history shifts by 1 day into slots 1..d-1.
        hist_hbits = self._rib_pair_hbits.get((prefix_bits, origin), 0)
        live_mask = (1 | ((hist_hbits << 1) & ((1 << self.window_days) - 1)))
        h_vec = [(live_mask >> j) & 1 for j in range(self.window_days)]
        s_t = sum(h * w for h, w in zip(h_vec, w_t)) / w_t_sum

        # Gather observed path ASNs from live update + historical node upstreams
        ups_live = set()
        if as_path:
            paths = clean_as_path(as_path) if isinstance(as_path, str) else [list(as_path)]
            for path in paths:
                for a in path[:-1]:
                    if not is_private_asn(int(a)) and int(a) != origin:
                        ups_live.add(int(a))

        # Add any historical upstreams stored at this exact node
        exact_node = self.root
        for bit in prefix_bits:
            exact_node = exact_node.children.get(bit)
            if exact_node is None:
                break
        if exact_node is not None:
            ups_live |= exact_node.rib_upstreams.get(origin, set())

        k1, k2, comp_space = self._rpki_irr_and_competitors(prefix_bits, origin)
        has_comp = bool(comp_space)
        s_m = 0.5 + (w1 * k1 + w2 * k2) / (2.0 * (w1 + w2))

        if not comp_space:
            best_rho = 1.0
        else:
            best_rho = 0.0
            for comp_asn, sp_hit in comp_space.items():
                r_val = self._relationship_score(origin, comp_asn, ups_live, sp_hit)
                if r_val > best_rho:
                    best_rho = r_val
                    if best_rho >= 1.0:
                        break
        rho_eff = 1.0 if k1 == 1 else best_rho

        # Update N(o) and Q(o) on first online sight of a pair absent from history RIB
        key = (prefix_bits, origin)
        if update_counters and key not in self._rib_pair_hbits and key not in self._online_seen_new:
            self._online_seen_new.add(key)
            self.origin_n_pfx[origin] += 1
            if has_comp and rho_eff == 0.0:
                self.origin_q_pfx[origin] += 1

        n_o = self.origin_n_pfx.get(origin, 0)
        q_o = self.origin_q_pfx.get(origin, 0)
        o_score = (1.0 - q_o / float(n_o)) if n_o > 0 else (0.0 if (has_comp and rho_eff == 0.0) else 1.0)
        s_r = min(rho_eff, o_score)

        return {
            "prefix": bits_to_ip_prefix(prefix_bits, self.ip_version),
            "prefix_bits": prefix_bits,
            "origin": int(origin),
            "has_rib": True,
            "has_comp": has_comp,
            "rpki_status": int(k1),
            "irr_status": int(k2),
            "time_persistence": float(s_t),
            "space_consistency": float(s_r),
            "source_consistency": float(s_m),
            "relation_score": float(rho_eff),
            "origin_consistency": float(o_score),
            "competing_origins": sorted(comp_space.keys()),
        }
