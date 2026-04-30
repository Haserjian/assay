We should adopt deterministic receipt hashes for outbound attestations.
The current approach reduces reviewability when identical payloads hash differently across implementations.
Canonical JSON plus SHA-256 gives us reproducible comparison across tools.
