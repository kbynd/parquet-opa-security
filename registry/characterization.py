"""
Single source of truth for bit assignments.
This is the contract between Step 1 (pipeline) and Step 2 (OPA + Spark filter).
Adding a new dimension = add entry here + update pipeline + update OPA policy.
Schema version bumps when bits are reassigned (never reuse a bit position).
"""

SCHEMA_VERSION = 1

# (word_index, bit_position)
# word_index 0 = _sec_lo, word_index 1 = _sec_hi
BITS = {
    # ── data_sensitivity (bits 0-3 of _sec_lo) ──────────────────────────
    "public":           (0, 0),
    "internal":         (0, 1),
    "confidential":     (0, 2),
    "restricted":       (0, 3),

    # ── regulatory_scope (bits 8-15 of _sec_lo) ─────────────────────────
    "pii":              (0, 8),
    "phi":              (0, 9),
    "financial":        (0, 10),
    "legal_privilege":  (0, 11),

    # ── origin_region (bits 16-23 of _sec_lo) ───────────────────────────
    "region_apac":      (0, 16),
    "region_emea":      (0, 17),
    "region_amer":      (0, 18),
    "region_global":    (0, 19),

    # ── data_type (bits 24-31 of _sec_lo) ───────────────────────────────
    "hr_data":          (0, 24),
    "customer_data":    (0, 25),
    "financial_record": (0, 26),
    "system_log":       (0, 27),
}


def bit_mask(dimension: str) -> tuple[int, int]:
    """Returns (lo_contribution, hi_contribution) for a dimension."""
    word, pos = BITS[dimension]
    if word == 0:
        return (1 << pos), 0
    else:
        return 0, (1 << (pos - 64))


def combine(*dimensions: str) -> tuple[int, int]:
    """OR together masks for a set of dimensions."""
    lo, hi = 0, 0
    for dim in dimensions:
        dl, dh = bit_mask(dim)
        lo |= dl
        hi |= dh
    return lo, hi


def decode(lo: int, hi: int) -> list[str]:
    """Return human-readable list of active dimensions for a bitmap."""
    active = []
    for name, (word, pos) in BITS.items():
        if word == 0 and (lo & (1 << pos)):
            active.append(name)
        elif word == 1 and (hi & (1 << (pos - 64))):
            active.append(name)
    return active
