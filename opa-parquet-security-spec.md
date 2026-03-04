# OPA-Parquet Security Architecture — Prototype Spec

## What this builds

A working Python prototype that demonstrates format-native data security for Parquet files,
using a two-step architecture:

- **Step 1 (characterization)**: A pipeline that stamps every row with a 128-bit security
  bitmap encoding what the data *is* (PII, financial, PHI, regional origin, sensitivity level).
  These are two extra Parquet columns: `_sec_lo` (INT64) and `_sec_hi` (INT64).

- **Step 2 (access decision)**: OPA (Open Policy Agent) is called once per `spark.read()`
  invocation. It takes the user's identity/roles and returns a permitted bitmap mask.
  A Spark filter — `(_sec_lo & forbidden_lo) == 0` — is injected transparently, before
  the caller sees any data.

The caller's code (`spark.read.parquet(path)`) is **completely unchanged**.

---

## Repository layout

```
opa-parquet-security/
├── README.md
├── docker-compose.yml          # OPA + (optional) MinIO for local S3
├── policies/
│   └── lakehouse.rego          # OPA policy
├── registry/
│   └── characterization.py     # Bit definitions (the schema contract)
├── pipeline/
│   └── characterize.py         # Step 1: stamps _sec_lo/_sec_hi on raw data
├── plugin/
│   └── opa_plugin.py           # spark.read() interceptor
├── tests/
│   ├── test_characterization.py
│   ├── test_opa_policy.py
│   └── test_end_to_end.py
├── data/
│   └── sample_raw.csv          # synthetic test data
└── notebooks/
    └── demo.ipynb              # walkthrough notebook
```

---

## Dependencies

```
# requirements.txt
pyspark==3.5.0
pyarrow==14.0.0
requests==2.31.0
pandas==2.1.0
pyyaml==6.0
pytest==7.4.0
```

OPA runs in Docker:
```yaml
# docker-compose.yml
version: "3.8"
services:
  opa:
    image: openpolicyagent/opa:latest-rootless
    ports:
      - "8181:8181"
    command: run --server --log-level=debug /policies
    volumes:
      - ./policies:/policies
```

---

## Component 1: Characterization Registry

```python
# registry/characterization.py
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
```

---

## Component 2: Characterization Pipeline

```python
# pipeline/characterize.py
"""
Step 1: Reads raw Parquet/CSV, derives _sec_lo and _sec_hi per row,
writes characterized Parquet to output path.

Rules are explicit and auditable. Each rule is a Python function that
inspects row fields and returns dimensions to assert.
In production, ML classifiers or regex engines plug in here.
"""

import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from registry.characterization import combine, SCHEMA_VERSION


# ── Characterization rules ────────────────────────────────────────────────────
# Each rule: (DataFrame) -> Series of (lo, hi) tuples

def rule_sensitivity(df: pd.DataFrame) -> pd.Series:
    """Derive sensitivity level from presence of sensitive fields."""
    def classify(row):
        dims = ["internal"]  # everything is at least internal
        if pd.notna(row.get("health_condition")) and row["health_condition"] != "":
            dims.append("restricted")
            dims.remove("internal")
        elif pd.notna(row.get("salary")) or pd.notna(row.get("annual_salary")):
            dims.append("confidential")
            dims.remove("internal")
        return combine(*dims)
    return df.apply(classify, axis=1)


def rule_regulatory(df: pd.DataFrame) -> pd.Series:
    """Detect regulatory scope from field content."""
    def classify(row):
        dims = []
        if pd.notna(row.get("email")) and "@" in str(row.get("email", "")):
            dims.append("pii")
        if pd.notna(row.get("health_condition")) and row["health_condition"] != "":
            dims.append("phi")
        if pd.notna(row.get("salary")) or pd.notna(row.get("annual_salary")):
            dims.append("financial")
        if pd.notna(row.get("ssn")) or pd.notna(row.get("tax_id")):
            dims.append("pii")
        return combine(*dims) if dims else (0, 0)
    return df.apply(classify, axis=1)


def rule_region(df: pd.DataFrame) -> pd.Series:
    """Map region field to origin bitmap."""
    REGION_MAP = {
        "APAC": "region_apac",
        "EMEA": "region_emea",
        "AMER": "region_amer",
        "GLOBAL": "region_global",
    }
    def classify(row):
        region = str(row.get("region", "")).upper().strip()
        dim = REGION_MAP.get(region)
        return combine(dim) if dim else (0, 0)
    return df.apply(classify, axis=1)


def rule_data_type(df: pd.DataFrame) -> pd.Series:
    """Classify data type from table/schema structure."""
    has_hr      = {"salary", "annual_salary", "department", "manager_id"}
    has_cust    = {"customer_id", "email", "name"}
    has_fin     = {"account_number", "transaction_id", "amount"}

    cols = set(df.columns)
    dims = []
    if cols & has_hr:      dims.append("hr_data")
    if cols & has_cust:    dims.append("customer_data")
    if cols & has_fin:     dims.append("financial_record")

    lo, hi = combine(*dims) if dims else (0, 0)
    return pd.Series([(lo, hi)] * len(df))


# ── Pipeline ──────────────────────────────────────────────────────────────────

RULES = [rule_sensitivity, rule_regulatory, rule_region, rule_data_type]


def characterize(df: pd.DataFrame) -> pd.DataFrame:
    """Apply all rules and compute final _sec_lo/_sec_hi per row."""
    lo = pd.Series([0] * len(df), dtype="int64")
    hi = pd.Series([0] * len(df), dtype="int64")

    for rule in RULES:
        result = rule(df)
        lo |= result.apply(lambda t: t[0]).astype("int64")
        hi |= result.apply(lambda t: t[1]).astype("int64")

    df = df.copy()
    df["_sec_lo"] = lo
    df["_sec_hi"] = hi
    # Embed schema version in table metadata
    return df


def run(input_path: str, output_path: str):
    """Characterize a CSV or Parquet file and write secured Parquet."""
    if input_path.endswith(".csv"):
        df = pd.read_csv(input_path)
    else:
        df = pd.read_parquet(input_path)

    characterized = characterize(df)

    table = pa.Table.from_pandas(characterized)

    # Embed schema version in Parquet file metadata
    existing_meta = table.schema.metadata or {}
    new_meta = {
        **existing_meta,
        b"security.characterization.schema_version": str(SCHEMA_VERSION).encode(),
    }
    table = table.replace_schema_metadata(new_meta)

    pq.write_table(table, output_path)
    print(f"Characterized {len(df)} rows → {output_path}")
    print(f"Schema version: {SCHEMA_VERSION}")


if __name__ == "__main__":
    import sys
    run(sys.argv[1], sys.argv[2])
    # python pipeline/characterize.py data/sample_raw.csv /tmp/secured/customers.parquet
```

---

## Component 3: OPA Policy

```rego
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
    "analyst":          {"internal", "customer_data"},
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
    lo := sum([BIT[d] | d := permitted_dims[_]; d in BIT])
}

permitted_hi := 0   # reserved for future use (bits 64-127)

# ── Result ────────────────────────────────────────────────────────────────────
result := {
    "permitted_lo":       permitted_lo,
    "permitted_hi":       permitted_hi,
    "allow":              true,
    "active_dimensions":  [d | d := permitted_dims[_]],
}
```

---

## Component 4: Spark Plugin

```python
# plugin/opa_plugin.py
"""
Installs a transparent security filter on spark.read().

Usage:
    from plugin.opa_plugin import install_opa_plugin, set_user_context

    spark = SparkSession.builder.appName("app").getOrCreate()
    install_opa_plugin(spark)

    set_user_context("kalyan@co.com", ["analyst", "apac_reader"], "IN")

    df = spark.read.parquet("path/to/secured/")   # ← unchanged
    df.show()                                      # ← only permitted rows
"""

import requests
import threading
import logging
from functools import wraps
from typing import Optional
from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F

logger = logging.getLogger(__name__)

# Thread-local user context — safe for concurrent notebook kernels / threads
_ctx = threading.local()


class OpaError(Exception):
    pass


class OpaClient:
    def __init__(self, url: str, timeout: int = 5):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def get_permitted_mask(self, user_id: str, roles: list, jurisdiction: str = "") -> tuple[int, int]:
        payload = {
            "input": {
                "user": {
                    "id": user_id,
                    "roles": roles,
                    "jurisdiction": jurisdiction,
                }
            }
        }
        try:
            resp = requests.post(
                f"{self.url}/v1/data/lakehouse/access/result",
                json=payload,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            result = resp.json().get("result", {})
            lo = result.get("permitted_lo", 0)
            hi = result.get("permitted_hi", 0)
            logger.debug(f"OPA permitted mask: lo={hex(lo)}, hi={hex(hi)}, "
                        f"dims={result.get('active_dimensions', [])}")
            return lo, hi
        except requests.RequestException as e:
            raise OpaError(f"OPA unreachable: {e}") from e


def set_user_context(user_id: str, roles: list, jurisdiction: str = ""):
    """Call once per session/request to establish who is reading data."""
    _ctx.user_id     = user_id
    _ctx.roles       = roles
    _ctx.jurisdiction = jurisdiction


def _current_user() -> dict:
    return {
        "user_id":      getattr(_ctx, "user_id", "anonymous"),
        "roles":        getattr(_ctx, "roles", []),
        "jurisdiction": getattr(_ctx, "jurisdiction", ""),
    }


def _apply_security_filter(df: DataFrame, opa_client: OpaClient, fail_open: bool) -> DataFrame:
    """
    Core enforcement logic.
    Called once per read — OPA called once, filter baked into plan.
    """
    # If table has no security columns, it's an unsecured table — pass through
    if "_sec_lo" not in df.columns:
        logger.debug("Table has no _sec_lo column — passing through unsecured")
        return df

    user = _current_user()

    try:
        permitted_lo, permitted_hi = opa_client.get_permitted_mask(
            user["user_id"], user["roles"], user["jurisdiction"]
        )
    except OpaError as e:
        if fail_open:
            logger.error(f"OPA error, failing open (INSECURE): {e}")
            return df.drop("_sec_lo", "_sec_hi")
        else:
            logger.error(f"OPA error, failing closed: {e}")
            # Return empty DataFrame with correct schema
            return df.filter(F.lit(False)).drop("_sec_lo", "_sec_hi")

    # forbidden_lo: bits that are set in the doc but NOT in permitted mask
    # A row is visible iff it has no forbidden bits
    # (_sec_lo & ~permitted_lo) == 0
    # Python int → Spark Long: mask to 63 bits (Spark Long is signed 64-bit)
    forbidden_lo = (~permitted_lo) & 0x7FFF_FFFF_FFFF_FFFF
    forbidden_hi = (~permitted_hi) & 0x7FFF_FFFF_FFFF_FFFF

    cond = F.col("_sec_lo").bitwiseAND(F.lit(forbidden_lo)) == F.lit(0)

    if "_sec_hi" in df.columns:
        cond = cond & (F.col("_sec_hi").bitwiseAND(F.lit(forbidden_hi)) == F.lit(0))

    return df.filter(cond).drop("_sec_lo", "_sec_hi")


def install_opa_plugin(
    spark: SparkSession,
    opa_url: str = "http://localhost:8181",
    fail_open: bool = False,
):
    """
    Monkey-patches DataFrameReader so that:
      spark.read.parquet(path)
      spark.read.load(path)
      spark.read.format(...).load(path)
      spark.table(name)
    all automatically apply OPA security filtering.

    fail_open=False (default, recommended): if OPA is unreachable, return empty DataFrame
    fail_open=True: if OPA is unreachable, return unfiltered data (INSECURE, dev only)
    """
    from pyspark.sql.readwriter import DataFrameReader

    client = OpaClient(opa_url)

    original_parquet = DataFrameReader.parquet
    original_load    = DataFrameReader.load
    original_table   = SparkSession.table

    @wraps(original_parquet)
    def secured_parquet(self, *paths, **options):
        df = original_parquet(self, *paths, **options)
        return _apply_security_filter(df, client, fail_open)

    @wraps(original_load)
    def secured_load(self, path=None, format=None, schema=None, **options):
        df = original_load(self, path=path, format=format, schema=schema, **options)
        return _apply_security_filter(df, client, fail_open)

    @wraps(original_table)
    def secured_table(self, tableName):
        df = original_table(self, tableName)
        return _apply_security_filter(df, client, fail_open)

    DataFrameReader.parquet = secured_parquet
    DataFrameReader.load    = secured_load
    SparkSession.table      = secured_table

    print(f"✓ OPA security plugin installed")
    print(f"  Policy endpoint : {opa_url}")
    print(f"  Fail mode       : {'open (INSECURE)' if fail_open else 'closed (safe)'}")
```

---

## Component 5: Sample Data

```csv
# data/sample_raw.csv
customer_id,name,email,annual_salary,region,health_condition,department
C001,Alice Smith,alice@example.com,95000,APAC,,Engineering
C002,Bob Jones,bob@example.com,120000,EMEA,,Finance
C003,Carol Lee,carol@example.com,85000,AMER,Diabetes,HR
C004,David Kim,david@example.com,110000,APAC,,Engineering
C005,Eve Patel,eve@example.com,75000,EMEA,,Marketing
C006,Frank Wu,frank@example.com,200000,APAC,Hypertension,Executive
C007,Grace Chen,grace@example.com,90000,AMER,,Engineering
C008,Hiro Tanaka,hiro@example.com,130000,APAC,,Finance
```

---

## Component 6: Tests

```python
# tests/test_characterization.py
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
from pipeline.characterize import characterize
from registry.characterization import bit_mask, decode

def make_row(**kwargs):
    return pd.DataFrame([{"customer_id": "X", "name": "Test", **kwargs}])


def test_pii_bit_set_when_email_present():
    df = make_row(email="test@example.com", region="APAC")
    result = characterize(df)
    pii_lo, _ = bit_mask("pii")
    assert result.iloc[0]["_sec_lo"] & pii_lo != 0, "PII bit should be set"


def test_phi_bit_set_when_health_condition_present():
    df = make_row(email="test@example.com", region="APAC", health_condition="Diabetes")
    result = characterize(df)
    phi_lo, _ = bit_mask("phi")
    assert result.iloc[0]["_sec_lo"] & phi_lo != 0, "PHI bit should be set"


def test_region_apac_bit():
    df = make_row(email="x@x.com", region="APAC")
    result = characterize(df)
    apac_lo, _ = bit_mask("region_apac")
    assert result.iloc[0]["_sec_lo"] & apac_lo != 0


def test_region_emea_bit():
    df = make_row(email="x@x.com", region="EMEA")
    result = characterize(df)
    emea_lo, _ = bit_mask("region_emea")
    assert result.iloc[0]["_sec_lo"] & emea_lo != 0


def test_no_double_application():
    """Running characterize twice should give same result (idempotent)."""
    df = make_row(email="x@x.com", region="APAC", annual_salary=100000)
    result1 = characterize(df)
    # Strip _sec_lo/_sec_hi and re-run
    stripped = result1.drop(columns=["_sec_lo", "_sec_hi"])
    result2 = characterize(stripped)
    assert result1.iloc[0]["_sec_lo"] == result2.iloc[0]["_sec_lo"]


def test_decode_roundtrip():
    df = make_row(email="x@x.com", region="APAC", health_condition="Flu", annual_salary=50000)
    result = characterize(df)
    lo = result.iloc[0]["_sec_lo"]
    dims = decode(lo, 0)
    assert "pii" in dims
    assert "phi" in dims
    assert "region_apac" in dims
    assert "financial" in dims
```

```python
# tests/test_end_to_end.py
"""
Requires: OPA running at localhost:8181 AND PySpark.
Run after: docker-compose up -d && python pipeline/characterize.py data/sample_raw.csv /tmp/test_secured.parquet
"""
import os
import pytest

OPA_URL = os.environ.get("OPA_URL", "http://localhost:8181")
PARQUET_PATH = "/tmp/test_secured.parquet"


@pytest.fixture(scope="module")
def spark():
    from pyspark.sql import SparkSession
    return SparkSession.builder.master("local[2]").appName("test").getOrCreate()


@pytest.fixture(scope="module")
def secured_parquet(spark):
    """Run characterization pipeline first."""
    import pandas as pd
    from pipeline.characterize import characterize
    import pyarrow as pa
    import pyarrow.parquet as pq

    df = pd.read_csv("data/sample_raw.csv")
    characterized = characterize(df)
    table = pa.Table.from_pandas(characterized)
    pq.write_table(table, PARQUET_PATH)
    return PARQUET_PATH


def test_apac_reader_sees_only_apac(spark, secured_parquet):
    from plugin.opa_plugin import install_opa_plugin, set_user_context
    install_opa_plugin(spark, opa_url=OPA_URL, fail_open=False)
    set_user_context("analyst@co.com", ["analyst", "apac_reader"], "IN")

    df = spark.read.parquet(secured_parquet)
    rows = df.collect()

    regions = {r["region"] for r in rows}
    assert regions == {"APAC"}, f"Expected only APAC rows, got: {regions}"


def test_phi_unauthorized_sees_no_health_records(spark, secured_parquet):
    from plugin.opa_plugin import install_opa_plugin, set_user_context
    install_opa_plugin(spark, opa_url=OPA_URL, fail_open=False)
    set_user_context("analyst@co.com", ["analyst", "apac_reader"], "IN")

    df = spark.read.parquet(secured_parquet)
    rows = df.collect()

    # Rows with health_condition should be excluded (phi bit set, not in permitted mask)
    health_rows = [r for r in rows if r.get("health_condition")]
    assert len(health_rows) == 0, "PHI rows should not be visible to unauthorized user"


def test_phi_authorized_sees_health_records(spark, secured_parquet):
    from plugin.opa_plugin import install_opa_plugin, set_user_context
    set_user_context("doctor@co.com", ["analyst", "phi_authorized", "apac_reader"], "IN")

    df = spark.read.parquet(secured_parquet)
    rows = df.collect()

    health_rows = [r for r in rows if r.get("health_condition")]
    assert len(health_rows) > 0, "PHI-authorized user should see health records"


def test_opa_unreachable_fails_closed(spark, secured_parquet):
    from plugin.opa_plugin import install_opa_plugin, set_user_context
    install_opa_plugin(spark, opa_url="http://localhost:9999", fail_open=False)
    set_user_context("analyst@co.com", ["analyst"], "IN")

    df = spark.read.parquet(secured_parquet)
    assert df.count() == 0, "Unreachable OPA with fail_open=False should return no rows"
```

---

## Running the prototype

```bash
# 1. Start OPA
docker-compose up -d

# 2. Install deps
pip install -r requirements.txt

# 3. Run characterization pipeline
python pipeline/characterize.py data/sample_raw.csv /tmp/secured/customers.parquet

# 4. Inspect what was written
python -c "
import pyarrow.parquet as pq
from registry.characterization import decode
t = pq.read_table('/tmp/secured/customers.parquet')
df = t.to_pandas()
for _, row in df.iterrows():
    dims = decode(row['_sec_lo'], row['_sec_hi'])
    print(f\"{row['name']:20s} _sec_lo={hex(row['_sec_lo'])}  {dims}\")
"

# 5. Run unit tests
pytest tests/test_characterization.py -v

# 6. Run end-to-end tests (requires OPA + Spark)
pytest tests/test_end_to_end.py -v

# 7. Interactive usage
python -c "
from pyspark.sql import SparkSession
from plugin.opa_plugin import install_opa_plugin, set_user_context

spark = SparkSession.builder.master('local[2]').appName('demo').getOrCreate()
install_opa_plugin(spark)

# APAC analyst — sees only APAC, no PHI
set_user_context('kalyan@co.com', ['analyst', 'apac_reader'], 'IN')
df = spark.read.parquet('/tmp/secured/customers.parquet')
print('APAC analyst sees:')
df.show()

# Finance reader — sees financial data, no PHI, all regions they have access to
set_user_context('finance@co.com', ['analyst', 'finance_reader', 'global_reader'], 'IN')
df2 = spark.read.parquet('/tmp/secured/customers.parquet')
print('Finance reader sees:')
df2.show()
"
```

---

## What this prototype validates

| Claim | How validated |
|---|---|
| Step 1 output is deterministic and auditable | `test_characterization.py` — rule-by-rule assertions |
| OPA called exactly once per read | Add `logging.DEBUG` — single OPA log entry per `spark.read()` |
| Caller code is unchanged | `spark.read.parquet(path)` — no security arguments |
| Fail-closed on OPA unreachable | `test_opa_unreachable_fails_closed` |
| PHI exclusion works | `test_phi_unauthorized_sees_no_health_records` |
| Regional filtering works | `test_apac_reader_sees_only_apac` |
| Bitmap is the only contract between Step 1 and Step 2 | OPA Rego never imports pipeline code; pipeline never imports Rego |

---

## What this defers (future hardening, not needed for prototype correctness)

1. **Row group skip**: Store OR bitmap in Parquet row group `key_value_metadata`.
   Custom `ParquetInputFormat` reads footer metadata and skips row groups with no
   intersection against permitted mask. Zero I/O for fully excluded groups.

2. **Manifest skip (Iceberg)**: Store OR bitmap in Iceberg manifest entries.
   Iceberg scan planner skips files at planning time before any S3 GetObject call.

3. **Scala Catalyst rule injection**: Replace Python monkey-patch with
   `SparkSessionExtensions.injectOptimizerRule`. Filter is injected at Catalyst
   level — Spark can push `bitwiseAND` predicate into Parquet scan statistics.

4. **Schema registry**: Version the bit definitions with migration tooling.
   Files written under schema version N remain readable under version N+1
   (new bits default to unset = most restrictive interpretation).

5. **ML classifiers for characterization**: Replace rule-based pipeline with
   ensemble: AWS Macie / Microsoft Presidio output → bit assignment.
   Confidence scoring → human review queue for low-confidence rows.

---

## Key invariant to preserve in all extensions

> OPA is called **once per query plan construction** (on the driver).  
> Spark executors **never call OPA**.  
> The permitted mask is a compile-time constant baked into the Filter node.  
> Security enforcement cost = one integer comparison per row.
