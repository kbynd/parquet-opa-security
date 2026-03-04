# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains a **prototype specification** for an OPA-Parquet security architecture that implements format-native data security for Parquet files. The system uses a two-step architecture:

1. **Characterization pipeline**: Stamps security metadata as 128-bit bitmaps (`_sec_lo` and `_sec_hi` columns) on Parquet rows
2. **Access control**: OPA (Open Policy Agent) evaluates user permissions and returns a bitmap mask that's applied as a transparent Spark filter

**Current state**: The repository contains only `opa-parquet-security-spec.md` — a complete specification with full code examples. The actual implementation has not been created yet.

## Architecture Components

### 1. Characterization Registry (`registry/characterization.py`)
- Single source of truth for bit assignments across 128-bit space
- Maps security dimensions to specific bit positions (e.g., `pii` → bit 8, `phi` → bit 9)
- Provides `bit_mask()`, `combine()`, and `decode()` utilities
- Schema versioning via `SCHEMA_VERSION` constant

**Bit space allocation**:
- Bits 0-3: Data sensitivity (`public`, `internal`, `confidential`, `restricted`)
- Bits 8-15: Regulatory scope (`pii`, `phi`, `financial`, `legal_privilege`)
- Bits 16-23: Origin region (`region_apac`, `region_emea`, `region_amer`, `region_global`)
- Bits 24-31: Data type (`hr_data`, `customer_data`, `financial_record`, `system_log`)
- Bits 32-63: Reserved for future use (`_sec_lo`)
- Bits 64-127: Reserved for future use (`_sec_hi`)

### 2. Characterization Pipeline (`pipeline/characterize.py`)
- Reads raw CSV/Parquet files
- Applies rule-based classification to derive security dimensions per row
- Writes Parquet with `_sec_lo` and `_sec_hi` columns
- Embeds schema version in Parquet metadata
- Rules are explicit Python functions (can be replaced with ML classifiers)

**Current rules**:
- `rule_sensitivity()`: Derives sensitivity level from field content
- `rule_regulatory()`: Detects PII/PHI/financial data
- `rule_region()`: Maps region field to bitmap
- `rule_data_type()`: Classifies based on column schema

### 3. OPA Policy (`policies/lakehouse.rego`)
- Role-based access control that maps user roles to permitted dimensions
- Returns `permitted_lo` and `permitted_hi` bitmaps
- Input: `{"user": {"id": "...", "roles": [...], "jurisdiction": "..."}}`
- Output: `{"permitted_lo": 12345, "permitted_hi": 0, "active_dimensions": [...]}`
- **Critical**: Bit definitions in Rego MUST match `registry/characterization.py`

### 4. Spark Plugin (`plugin/opa_plugin.py`)
- Monkey-patches `spark.read.parquet()`, `spark.read.load()`, and `spark.table()`
- Calls OPA **once per query** (not per row) to get permitted mask
- Injects transparent filter: `(_sec_lo & forbidden_mask) == 0`
- Thread-safe user context via `set_user_context(user_id, roles, jurisdiction)`
- Fail-closed by default (returns empty DataFrame if OPA unreachable)

**Key invariant**: OPA is called on the driver during query planning. Executors never call OPA. The security filter is a compile-time constant bitmap comparison.

## Implementation Commands

The specification includes commands for when the code is implemented:

### Running the system
```bash
# Start OPA server
docker-compose up -d

# Install dependencies
pip install -r requirements.txt

# Run characterization pipeline
python pipeline/characterize.py data/sample_raw.csv /tmp/secured/customers.parquet

# Inspect characterized data
python -c "
import pyarrow.parquet as pq
from registry.characterization import decode
t = pq.read_table('/tmp/secured/customers.parquet')
df = t.to_pandas()
for _, row in df.iterrows():
    dims = decode(row['_sec_lo'], row['_sec_hi'])
    print(f\"{row['name']:20s} _sec_lo={hex(row['_sec_lo'])}  {dims}\")
"
```

### Testing
```bash
# Unit tests for characterization logic
pytest tests/test_characterization.py -v

# Integration tests for OPA policy
pytest tests/test_opa_policy.py -v

# End-to-end tests (requires OPA + PySpark)
pytest tests/test_end_to_end.py -v
```

### Interactive usage with Spark
```python
from pyspark.sql import SparkSession
from plugin.opa_plugin import install_opa_plugin, set_user_context

spark = SparkSession.builder.master('local[2]').appName('demo').getOrCreate()
install_opa_plugin(spark)

# Set user context
set_user_context('user@company.com', ['analyst', 'apac_reader'], 'IN')

# Read secured data (filter applied transparently)
df = spark.read.parquet('/tmp/secured/customers.parquet')
df.show()
```

## Critical Implementation Rules

### Bit assignment consistency
The bit definitions in three places MUST stay synchronized:
1. `registry/characterization.py` → `BITS` dict
2. `policies/lakehouse.rego` → `BIT` object
3. Any documentation or schema registry

**Never reuse a bit position**. Bump `SCHEMA_VERSION` when changing bit assignments.

### Security filter mathematics
- `permitted_mask`: Bitmap of dimensions the user can see
- `forbidden_mask = ~permitted_mask`: Bitmap of dimensions the user cannot see
- A row is visible iff: `(row._sec_lo & forbidden_mask) == 0`
- Must mask to 63 bits (`& 0x7FFF_FFFF_FFFF_FFFF`) because Spark Long is signed 64-bit

### OPA integration
- OPA must be reachable at query planning time (driver only)
- Default to `fail_open=False` (fail-closed) in production
- Use `fail_open=True` only for development/debugging
- Thread-local user context ensures safety in multi-threaded environments

### Performance characteristics
- OPA called once per `spark.read()` invocation (not per row, not per partition)
- Filter is pushed down to Parquet scan statistics when possible
- Enforcement cost = one integer comparison per row (bitwise AND)

## Future Enhancements (deferred from prototype)

1. **Row group skip**: Store OR bitmap in Parquet row group metadata to skip entire row groups during scan
2. **Iceberg manifest skip**: Store bitmap in manifest entries for file-level filtering
3. **Catalyst rule injection**: Replace monkey-patch with proper Spark optimizer rule
4. **Schema registry**: Version control for bit definitions with migration tooling
5. **ML-based characterization**: Replace rule-based classification with ML classifiers (AWS Macie, Microsoft Presidio)

## Testing Strategy

### Unit tests (`test_characterization.py`)
- Verify correct bit setting for each dimension
- Test idempotency of characterization
- Validate decode/encode round-trip

### Integration tests (`test_opa_policy.py`)
- Test role-to-permission mapping
- Verify bitmap calculation correctness

### End-to-end tests (`test_end_to_end.py`)
- Requires running OPA server
- Tests regional filtering (APAC reader sees only APAC rows)
- Tests PHI exclusion (unauthorized users don't see health records)
- Tests fail-closed behavior when OPA unreachable

## Dependencies

```
pyspark==3.5.0
pyarrow==14.0.0
requests==2.31.0
pandas==2.1.0
pyyaml==6.0
pytest==7.4.0
```

OPA runs in Docker (see `docker-compose.yml` in spec).
