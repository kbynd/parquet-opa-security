# policies/lakehouse.rego
package lakehouse.access

# ── Input shape ───────────────────────────────────────────────────────────────
# {
#   "input": {
#     "user": {
#       "id": "kalyan@company.com",
#       "roles": ["analyst", "apac_reader"],
#       "jurisdiction": "IN",
#       "auth_level": "mfa"          # optional
#     },
#     "table": "customers"           # optional, for table-specific policies
#   }
# }
#
# ── Output shape ──────────────────────────────────────────────────────────────
# GET /v1/data/lakehouse/access/result
# {
#   "result": {
#     "permitted_lo": 12345,
#     "permitted_hi": 0,
#     "allow": true,
#     "active_dimensions": ["internal", "pii", "region_apac"]
#   }
# }

import future.keywords.if
import future.keywords.in

# ── Bit definitions (must match registry/characterization.py) ─────────────────
BIT = {
    "public":           1,
    "internal":         2,
    "confidential":     4,
    "restricted":       8,
    "pii":              256,
    "phi":              512,
    "financial":        1024,
    "legal_privilege":  2048,
    "region_apac":      65536,
    "region_emea":      131072,
    "region_amer":      262144,
    "region_global":    524288,
    "hr_data":          16777216,
    "customer_data":    33554432,
    "financial_record": 67108864,
    "system_log":       134217728,
}

# ── Base permissions (all authenticated users) ────────────────────────────────
base_dims := {"public", "internal"}

# ── Role → dimension grants ───────────────────────────────────────────────────
role_grants := {
    "analyst":          {"internal", "confidential", "customer_data", "pii", "financial", "hr_data"},
    "finance_reader":   {"financial", "financial_record", "confidential"},
    "hr_reader":        {"hr_data", "confidential"},
    "pii_authorized":   {"pii"},
    "phi_authorized":   {"phi", "restricted"},
    "apac_reader":      {"region_apac"},
    "emea_reader":      {"region_emea"},
    "amer_reader":      {"region_amer"},
    "global_reader":    {"region_global", "region_apac", "region_emea", "region_amer"},
    "admin":            {
        "public", "internal", "confidential", "restricted",
        "pii", "phi", "financial", "legal_privilege",
        "region_apac", "region_emea", "region_amer", "region_global",
        "hr_data", "customer_data", "financial_record", "system_log"
    },
}

# ── Compute permitted dimensions for this user ────────────────────────────────
permitted_dims := dims if {
    role_dims := {d | role := input.user.roles[_]; d := role_grants[role][_]}
    dims := base_dims | role_dims
}

# ── Convert to bitmap ─────────────────────────────────────────────────────────
permitted_lo := lo if {
    lo := sum([BIT[d] | some d; permitted_dims[d]; BIT[d]])
}

permitted_hi := 0   # reserved for future use (bits 64-127)

# ── Result ────────────────────────────────────────────────────────────────────
result := {
    "permitted_lo":       permitted_lo,
    "permitted_hi":       permitted_hi,
    "allow":              true,
    "active_dimensions":  [d | d := permitted_dims[_]],
}
