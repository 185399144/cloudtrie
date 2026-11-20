"""DetectTrie data structure for fast O(L) online BGP hijack detection.

Stores trusted P/O mappings (uncertainty u < th_pro) and supports both exact
prefix lookup and RFC 6811 covering-prefix lookup (Cover/Match rules for
Valid, Hijack, Sub_Hijack, and NotFound classification).
"""

from collections import defaultdict
from pathlib import Path
import pickle


class DetectTrieNode:
    """Memory-compact binary trie node storing trusted origin ASes."""

    __slots__ = ("children", "source_as_set")

    def __init__(self):
        self.children = {"0": None, "1": None}
        self.source_as_set = set()


class DetectTrie:
    """Binary prefix detection trie for trusted P/O mappings."""

    def __init__(self, min_prefix_len: int = 8):
        self.root = DetectTrieNode()
        self.min_prefix_len = int(min_prefix_len)
        self.conflict_log = defaultdict(set)

    def insert(self, binary_prefix: str, source_as: int) -> None:
        """Insert a trusted (binary_prefix, origin_asn) mapping (supports MOAS)."""
        node = self.root
        for bit in binary_prefix:
            nxt = node.children[bit]
            if nxt is None:
                nxt = DetectTrieNode()
                node.children[bit] = nxt
            node = nxt

        origin = int(source_as)
        if node.source_as_set and origin not in node.source_as_set:
            self.log_conflict(binary_prefix, node.source_as_set, origin)
        node.source_as_set.add(origin)

    def log_conflict(self, prefix: str, existing_as, new_as: int) -> None:
        """Record multi-origin (MOAS) prefixes."""
        self.conflict_log[prefix].update(existing_as)
        self.conflict_log[prefix].add(new_as)

    def batch_insert(self, po_pairs) -> None:
        """Batch insert (binary_prefix, origin_asn) pairs."""
        for prefix, asn in po_pairs:
            self.insert(prefix, asn)

    def search(self, binary_prefix: str):
        """Exact-match lookup returning the trusted origin AS set, or None."""
        node = self.root
        for bit in binary_prefix:
            node = node.children.get(bit)
            if node is None:
                return None
        return node.source_as_set if node.source_as_set else None

    def search_with_fallback(self, binary_prefix: str):
        """Longest-prefix covering match along binary_prefix (depth >= min_prefix_len).

        Returns:
            (as_set, matched_prefix_length, is_exact_match)
        """
        node = self.root
        best_set = None
        best_len = 0
        plen = len(binary_prefix)

        for depth, bit in enumerate(binary_prefix, start=1):
            node = node.children.get(bit)
            if node is None:
                break
            if depth >= self.min_prefix_len and node.source_as_set:
                best_set = node.source_as_set
                best_len = depth

        if best_set is None:
            return set(), 0, False
        return set(best_set), best_len, (best_len == plen)

    def classify(self, binary_prefix: str, origin_asn: int):
        """Classify an announcement using RFC 6811 Cover/Match rules (Eqs. 11-15).

        Returns:
            (status, matched_as_set, matched_prefix_length)
            where status is one of: 'valid', 'hijack', 'sub_hijack', 'not_found'.
        """
        origin = int(origin_asn)
        as_set, matched_len, is_exact = self.search_with_fallback(binary_prefix)
        if not as_set:
            return "not_found", set(), 0
        if origin in as_set:
            return "valid", as_set, matched_len
        if is_exact:
            return "hijack", as_set, matched_len
        return "sub_hijack", as_set, matched_len

    def save(self, file_path) -> None:
        """Persist DetectTrie to disk."""
        p = Path(file_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("wb") as f:
            pickle.dump(
                {"root": self.root, "min_prefix_len": self.min_prefix_len},
                f,
                protocol=pickle.HIGHEST_PROTOCOL,
            )

    @staticmethod
    def load(file_path):
        """Load DetectTrie from disk."""
        with Path(file_path).open("rb") as f:
            payload = pickle.load(f)
        trie = DetectTrie()
        if isinstance(payload, dict) and "root" in payload:
            trie.root = payload["root"]
            trie.min_prefix_len = int(payload.get("min_prefix_len", 8))
        else:
            trie.root = payload
        return trie
