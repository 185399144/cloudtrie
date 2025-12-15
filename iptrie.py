import datetime
import pickle
import ipaddress
from collections import defaultdict
from pathlib import Path


def default_list():
    return [0] * 5


def default_source_dict():
    return defaultdict(default_list)


def default_peer_dict():
    return defaultdict(default_list)


def ip_prefix_to_bits(prefix):
    net = ipaddress.ip_network(prefix, strict=False)
    bitlen = net.max_prefixlen
    addr_int = int(net.network_address)
    bits = bin(addr_int)[2:].zfill(bitlen)
    return bits[: net.prefixlen]


class TrieNode:
    def __init__(self):
        self.children = {'0': None, '1': None}
        self.is_end_of_prefix = False
        self.sources = defaultdict(default_source_dict)
        self.peers = defaultdict(default_peer_dict)

    def get_day_from_date(self, date):
        if date is None:
            return 0
        start_date = datetime.date(2024, 7, 1)
        return (date - start_date).days

    def update_source(self, source_as, source, announced, date, peer_as):
        day = self.get_day_from_date(date) % 5
        if 0 <= day < 5:
            self.sources[source_as][source][day] = 1 if announced else 0
            if peer_as:
                self.peers[source_as][peer_as][day] = 1


class IPTrie:
    def __init__(self, as_relationships=None):
        self.root = TrieNode()
        self.as_relationships = as_relationships or {}

    def insert(self, ip_prefix, source_as, source, announced, date, peer_as):
        node = self.root
        for bit in ip_prefix:
            if node.children[bit] is None:
                node.children[bit] = TrieNode()
            node = node.children[bit]
        node.is_end_of_prefix = True
        node.update_source(source_as, source, announced, date, peer_as)

    def search(self, ip):
        node = self.root
        for bit in ip:
            if node.children.get(bit) is None:
                return None
            node = node.children[bit]
        if node.is_end_of_prefix:
            return node.sources, node.peers
        return None

    def save_to_file(self, file_path):
        file_path = Path(file_path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open('wb') as f:
            pickle.dump(self, f)

    @staticmethod
    def load_from_file(file_path):
        with Path(file_path).open('rb') as f:
            return pickle.load(f)

    def _dfs(self, node, prefix_bits, out):
        if node.is_end_of_prefix:
            out.append((prefix_bits, node))
        for bit, child in node.children.items():
            if child is not None:
                self._dfs(child, prefix_bits + bit, out)

    def iter_prefix_nodes(self):
        out = []
        self._dfs(self.root, "", out)
        return out

    def collect_po_pairs(self):
        import math
        # Time decay weights
        weights = [math.exp(-i / 2) for i in range(5)]
        
        # Source consistency weights - cumulative
        SOURCE_WEIGHTS = {'RIB': 0.26, 'IRR': 0.36, 'RPKI': 0.38}

        po_list = []
        for prefix_bits, node in self.iter_prefix_nodes():
            for origin_asn, sources_dict in node.sources.items():
                sources = set(sources_dict.keys())
                
                # Merge days arrays from all sources
                time_vectors = [0] * 5
                rib_days = [0] * 5

                for source, days_list in sources_dict.items():
                    for day in range(5):
                        if days_list[day]:
                            time_vectors[day] += 1
                            if source.upper() == "RIB":
                                rib_days[day] = 1

                # Time persistence: exponential decay weighting
                time_sum = sum(time_vectors)
                if time_sum > 0:
                    time_persistence = sum(t * w for t, w in zip(time_vectors, weights)) / time_sum
                else:
                    time_persistence = 0.0

                # Space consistency: log1p(peer_count)
                peers_dict = node.peers.get(origin_asn, {})
                peer_count = len(peers_dict)
                space_consistency = math.log1p(peer_count)

                sources_upper = {str(s).upper() for s in sources}
                has_rib = "RIB" in sources_upper and any(rib_days)

                # Source consistency: cumulative weighting
                source_consistency = sum(SOURCE_WEIGHTS.get(s, 0) for s in sources_upper)

                po_list.append(
                    {
                        "prefix_bits": prefix_bits,
                        "origin": int(origin_asn),
                        "sources": sorted(sources_upper),
                        "has_rib": bool(has_rib),
                        "peer_count": int(peer_count),
                        "time_vectors": time_vectors,
                        "time_persistence": float(time_persistence),
                        "space_consistency": float(space_consistency),
                        "source_consistency": float(source_consistency),
                    }
                )

        return po_list
