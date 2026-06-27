"""Shadow-header governance for HYDRA artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


REQUIRED_HEADER_FIELDS = (
    "title",
    "version",
    "author",
    "date",
    "status",
    "artifact_class",
    "claim_type",
    "evidence_basis",
    "boundary_of_validity",
    "primary_drift_risk",
    "core_invariant",
    "memory_compression_anchor",
    "cross_canon_alignment",
    "source_extraction",
    "empirical_confidence_badge",
    "purpose",
    "evolution_gate",
    "terminology_stability",
    "non_claims",
)


@dataclass(frozen=True)
class ArtifactHeader:
    fields: dict[str, str]

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "ArtifactHeader":
        return cls({str(key): str(value).strip() for key, value in raw.items()})


def archive_gate(header: ArtifactHeader | dict[str, Any]) -> dict[str, Any]:
    if isinstance(header, dict):
        header = ArtifactHeader.from_raw(header)
    missing = [field for field in REQUIRED_HEADER_FIELDS if not header.fields.get(field)]
    non_claims = header.fields.get("non_claims", "").lower()
    non_claim_lock = all(token in non_claims for token in ("not", "universal", "validated"))
    ready = not missing and non_claim_lock
    actions = []
    if missing:
        actions.append("complete missing shadow-header fields")
    if not non_claim_lock:
        actions.append("state explicit non-claims, including what is not validated or universal")
    return {
        "archive_ready": ready,
        "missing_fields": missing,
        "non_claim_lock": non_claim_lock,
        "required_actions": actions,
    }

