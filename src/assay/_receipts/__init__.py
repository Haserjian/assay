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

__all__: list[str] = [
    # tri_temporal exports (not available in vendored subset):
    # "Lineage",
    # "Proof",
    # "TransactionTime",
    # "TriTemporalReceipt",
    # "ValidTime",
    # "compute_receipt_hash",
    # "sign_and_timestamp_receipt",
    # "verify_receipt_signature",
    # "attach_lineage",
    # "TRI_TEMPORAL_SCHEMA_ID",
]
