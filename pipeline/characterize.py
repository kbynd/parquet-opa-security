"""
Step 1: Reads raw Parquet/CSV, derives _sec_lo and _sec_hi per row,
writes characterized Parquet to output path.

Rules are explicit and auditable. Each rule is a Python function that
inspects row fields and returns dimensions to assert.
In production, ML classifiers or regex engines plug in here.

NOTE: The article (opa-parquet-security-article.md) shows a simplified
version of this characterization logic for readability. This is the full,
production-ready implementation with separate rule functions, metadata
embedding, and schema versioning.
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
