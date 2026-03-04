# OPA-Parquet Security Prototype

A working Python prototype that demonstrates format-native data security for Parquet files, using a two-step architecture:

- **Step 1 (characterization)**: A pipeline that stamps every row with a 128-bit security bitmap encoding what the data *is* (PII, financial, PHI, regional origin, sensitivity level). These are two extra Parquet columns: `_sec_lo` (INT64) and `_sec_hi` (INT64).

- **Step 2 (access decision)**: OPA (Open Policy Agent) is called once per `spark.read()` invocation. It takes the user's identity/roles and returns a permitted bitmap mask. A Spark filter — `(_sec_lo & forbidden_lo) == 0` — is injected transparently, before the caller sees any data.

The caller's code (`spark.read.parquet(path)`) is **completely unchanged**.

## Quick Start

### 1. Start OPA

```bash
docker-compose up -d
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run characterization pipeline

```bash
python pipeline/characterize.py data/sample_raw.csv /tmp/secured/customers.parquet
```

### 4. Inspect characterized data

```bash
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

### 5. Run tests

```bash
# Unit tests
pytest tests/test_characterization.py -v

# End-to-end tests (requires OPA + Spark)
pytest tests/test_end_to_end.py -v
```

### 6. Interactive usage

```python
from pyspark.sql import SparkSession
from plugin.opa_plugin import install_opa_plugin, set_user_context

spark = SparkSession.builder.master('local[2]').appName('demo').getOrCreate()
install_opa_plugin(spark)

# APAC analyst — sees only APAC, no PHI
set_user_context('kbynd@co.com', ['analyst', 'apac_reader'], 'IN')
df = spark.read.parquet('/tmp/secured/customers.parquet')
df.show()

# Finance reader — sees financial data, no PHI
set_user_context('finance@co.com', ['analyst', 'finance_reader', 'global_reader'], 'IN')
df2 = spark.read.parquet('/tmp/secured/customers.parquet')
df2.show()
```

## Reading with the Article

If you're coming from the article **"Securing Parquet at the Source: A Format-Native Approach Using Bitmaps and OPA"** ([opa-parquet-security-article.md](opa-parquet-security-article.md)), here's how the code maps to what's described:

### Core Files Featured in Article

- **`registry/characterization.py`** - The bit schema (article lines 33-58). Shows the exact `BITS` dictionary mapping security dimensions to bit positions.

- **`policies/lakehouse.rego`** - The OPA policy (article lines 103-138). Defines role grants and computes permitted bitmaps.

- **`plugin/opa_plugin.py`** - The Spark integration (article lines 167-196). Implements the transparent security filter injection.

- **`tests/test_end_to_end.py`** - Validation tests (article lines 206-229). Proves regional filtering, PHI protection, and fail-closed behavior.

- **`pipeline/characterize.py`** - Full characterization pipeline. The article shows a simplified inline version for readability (lines 62-86), while this file contains the complete implementation with separate rule functions, metadata embedding, and schema versioning.

### Quick Demo Matching Article Examples

```bash
# Run the complete demo
python demo.py

# Or run individual tests as shown in the article
pytest tests/test_end_to_end.py::test_apac_reader_sees_only_apac -v
pytest tests/test_end_to_end.py::test_phi_unauthorized_sees_no_health_records -v
```

## Architecture

See [opa-parquet-security-spec.md](opa-parquet-security-spec.md) for detailed architecture documentation.

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
