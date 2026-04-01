"""
Receipts module exports (vendored subset for assay).

NOTE: tri_temporal is not vendored into assay. The imports below are
commented out because the module does not exist in the vendored _receipts
package. If tri_temporal support is needed, vendor the module or install
the full receipts package.
"""

# tri_temporal is NOT vendored -- commented out to avoid ImportError
# from assay._receipts.tri_temporal import (
#     Lineage,
#     Proof,
#     TransactionTime,
#     TriTemporalReceipt,
#     ValidTime,
#     compute_receipt_hash,
#     sign_and_timestamp_receipt,
#     verify_receipt_signature,
#     attach_lineage,
#     TRI_TEMPORAL_SCHEMA_ID,
# )

from assay._receipts.v2_types import (
    SigEntry,
    VerificationBundle,
    PolicyRequires,
    VerificationPolicy,
    ALGORITHM_STATUS,
    OPERATIONAL_ALGORITHMS,
    ARCHIVAL_ALGORITHMS,
    UNSUPPORTED_ALGORITHMS,
)
from assay._receipts.canonicalize import (
    canonical_projection,
    compute_bundle_digest,
    parse_ijson_receipt,
    PROJECTION_DOCTRINE,      # authoritative location — canonicalize.py
    PROJECTION_EXCLUSIONS,    # public alias for live exclusion sets
)
from assay._receipts.v2_sign import emit_v2_receipt, default_v2_policy, build_v2_base_receipt
from assay._receipts.v2_verify import SigResult, VerifyResultV2, verify_v2

__all__: list[str] = [
    # v2 schema types
    "SigEntry",
    "VerificationBundle",
    "PolicyRequires",
    "VerificationPolicy",
    "ALGORITHM_STATUS",
    "OPERATIONAL_ALGORITHMS",
    "ARCHIVAL_ALGORITHMS",
    "UNSUPPORTED_ALGORITHMS",
    # v2 canonicalization + parse
    "canonical_projection",
    "compute_bundle_digest",
    "parse_ijson_receipt",
    # v2 doctrine (authoritative: canonicalize.py)
    "PROJECTION_DOCTRINE",
    "PROJECTION_EXCLUSIONS",
    # v2 signing
    "emit_v2_receipt",
    "default_v2_policy",
    "build_v2_base_receipt",
    # v2 verifier
    "SigResult",
    "VerifyResultV2",
    "verify_v2",
    # tri_temporal exports (not available in vendored subset):
    # "Lineage",
    # ...
]
