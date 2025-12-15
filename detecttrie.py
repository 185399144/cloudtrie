from collections import defaultdict
import pickle


class DetectTrieNode:
    """Optimized DetectTrie node structure"""
    __slots__ = ['children', 'source_as_set']
    
    def __init__(self):
        self.children = {'0': None, '1': None}
        self.source_as_set = set()


class DetectTrie:
    """Efficient prefix detection tree"""   
    def __init__(self):
        self.root = DetectTrieNode()
        self.conflict_log = defaultdict(set)

    def insert(self, binary_prefix: str, source_as: int) -> None:
        """Insert binary prefix with conflict detection"""
        node = self.root
        for bit in binary_prefix:
            if not node.children[bit]:
                node.children[bit] = DetectTrieNode()
            node = node.children[bit]

        source_as = int(source_as)
        if node.source_as_set:
            if source_as not in node.source_as_set:
                self.log_conflict(binary_prefix, node.source_as_set, source_as)
        else:
            node.source_as_set.add(source_as)

    def log_conflict(self, prefix, existing_as, new_as):
        """Log prefix conflict event"""
        self.conflict_log[prefix].update(existing_as)
        self.conflict_log[prefix].add(new_as)

    def batch_insert(self, po_pairs):
        """Batch insert P/O pairs"""
        for prefix, asn in po_pairs:
            self.insert(prefix, asn)

    def search(self, binary_prefix: str):
        """Search for legal AS set corresponding to binary prefix"""
        node = self.root
        for bit in binary_prefix:
            if node.children[bit] is None:
                return None
            node = node.children[bit]
        return node.source_as_set if node.source_as_set else None

    def save(self, file_path) -> None:
        """Save DetectTrie to file"""
        file_path = str(file_path)
        with open(file_path, 'wb') as f:
            pickle.dump(self.root, f)

    @staticmethod
    def load(file_path):
        """Load DetectTrie from file"""
        file_path = str(file_path)
        trie = DetectTrie()
        with open(file_path, 'rb') as f:
            trie.root = pickle.load(f)
        return trie
