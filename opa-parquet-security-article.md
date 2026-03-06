# Securing Parquet at the Source: A Format-Native Approach Using Bitmaps and OPA

*What if data carried its own security classification — as a physical column in the Parquet file — so that any reader could enforce access correctly, regardless of which engine or catalog is in use? This article describes that idea, a working prototype, and why the separation of "what is this data" from "who can see it" turns out to be the key move.*

---

## Two Questions That Are Usually Conflated

When you think about securing a row of data in a lakehouse, there are really two separate questions:

**What is this data?**
A row containing an email address, a medical diagnosis, and a salary figure is — simultaneously — PII, PHI, and financial data. That characterization is a property of the row's *content*. It is deterministic, derivable at write time, and stable unless the document changes. It has nothing to do with who is querying it.

**Can this principal see it?**
Whether a given user can read that row depends on their roles, their jurisdiction, the purpose of the query, active legal holds, and many other factors that change dynamically. This is a property of the *intersection* of the user's context and the data's characterization.

Most lakehouse security architectures collapse these two questions into a single operation evaluated at query time — by the catalog, or by the engine, or both. That works as long as every query goes through the right engine or catalog. The moment someone reads raw Parquet files directly from S3 with PyArrow, or switches to an engine that hasn't implemented the right plugin, the guarantee disappears.

The approach here is different: answer the first question at *write time* and store the answer durably in the Parquet file itself. Answer the second question once at query *planning* time, using OPA. The bitmap in the file is the contract between the two steps.

The result is a prototype where `spark.read.parquet(path)` returns only the rows a user is permitted to see — with no changes to the calling code, no per-row OPA calls, and security metadata that travels with the file regardless of which system reads it next.

---

## The Architecture

### Step 1: Data Characterization (write time)

Every row in a secured Parquet table carries two additional columns: `_sec_lo` (INT64) and `_sec_hi` (INT64). Together they form a 128-bit bitmap encoding the row's security-relevant characteristics.

The bit positions are defined in a registry — a simple shared schema that both the write pipeline and the OPA policy must agree on:

```python
BITS = {
    # data_sensitivity (bits 0-3)
    "public":           (0, 0),
    "internal":         (0, 1),
    "confidential":     (0, 2),
    "restricted":       (0, 3),

    # regulatory_scope (bits 8-15)
    "pii":              (0, 8),
    "phi":              (0, 9),
    "financial":        (0, 10),
    "legal_privilege":  (0, 11),

    # origin_region (bits 16-23)
    "region_apac":      (0, 16),
    "region_emea":      (0, 17),
    "region_amer":      (0, 18),
    "region_global":    (0, 19),

    # data_type (bits 24-31)
    "hr_data":          (0, 24),
    "customer_data":    (0, 25),
    "financial_record": (0, 26),
}
```

A characterization pipeline reads raw data and computes these columns per row using explicit, auditable rules:

```python
def characterize(df: pd.DataFrame) -> pd.DataFrame:
    lo = pd.Series([0] * len(df), dtype="int64")

    # PII: email field present
    lo |= df["email"].notna().apply(lambda v: (1 << 8) if v else 0)

    # PHI: health condition present
    lo |= df["health_condition"].notna().apply(lambda v: (1 << 9) if v else 0)

    # Financial: salary field present
    lo |= df["annual_salary"].notna().apply(lambda v: (1 << 10) if v else 0)

    # Region
    region_map = {"APAC": 1 << 16, "EMEA": 1 << 17, "AMER": 1 << 18}
    lo |= df["region"].map(lambda r: region_map.get(r.upper(), 0))

    # Sensitivity: escalate rows with PII or PHI to restricted
    lo |= lo.apply(lambda v: (1 << 3) if (v & (1<<8) or v & (1<<9)) else (1 << 1))

    df = df.copy()
    df["_sec_lo"] = lo
    df["_sec_hi"] = pd.Series([0] * len(df), dtype="int64")
    return df
```

The output is a Parquet file where every row carries a compact, machine-readable summary of what it contains in security-relevant terms. The `_sec_lo` value for a row containing an email, a health condition, and an APAC region flag would look like:

```
_sec_lo = 0x00030708
          ↑↑ sensitivity: restricted (bit 3) + internal (bit 1)
            ↑↑ regulatory: pii (bit 8) + phi (bit 9)
              ↑↑ region: apac (bit 16)
```

Importantly, this is a data classification problem, not a security policy problem. It is deterministic, testable, and auditable. In production, rule-based classification can be augmented with ML classifiers (AWS Macie, Microsoft Presidio) for PII and PHI detection, with confidence scoring feeding a human review queue for low-confidence rows.

### Step 2: Access Decision (query planning time)

OPA is called once per `spark.read()` invocation, before any executor touches any data. It receives the user's identity and roles and returns a *permitted bitmap* — the set of characterization dimensions this principal is allowed to see.

```rego
# policies/lakehouse.rego
package lakehouse.access

BIT = {
    "public":        1,    "internal":    2,
    "confidential":  4,    "restricted":  8,
    "pii":           256,  "phi":         512,
    "financial":     1024,
    "region_apac":   65536, "region_emea": 131072,
    "region_amer":   262144,
    # ...
}

role_grants := {
    "analyst":        {"internal", "customer_data"},
    "finance_reader": {"financial", "financial_record", "confidential"},
    "pii_authorized": {"pii"},
    "phi_authorized": {"phi", "restricted"},
    "apac_reader":    {"region_apac"},
    "global_reader":  {"region_apac", "region_emea", "region_amer", "region_global"},
}

permitted_dims := base_dims | {d |
    role := input.user.roles[_]
    d    := role_grants[role][_]
}

permitted_lo := sum([BIT[d] | d := permitted_dims[_]; d in BIT])

result := {
    "permitted_lo": permitted_lo,
    "permitted_hi": 0,
    "allow":        true,
}
```

The OPA call is a single HTTP POST on the driver. The response is two integers. The permitted mask is then baked into a Spark filter as a compile-time literal:

```
forbidden_lo = ~permitted_lo & 0x7FFF_FFFF_FFFF_FFFF
Filter: (_sec_lo & forbidden_lo) == 0
```

This filter reads: *"exclude rows that have any characterization bits the user is not permitted to see."* It is a bitwise AND on a fixed-width integer column. Every row that passes has only characteristics within the user's permitted set.

### The Spark Plugin

The enforcement is wired in transparently by patching `DataFrameReader` at session startup. The caller's code is completely unchanged:

```python
# Install once at session startup
install_opa_plugin(spark, opa_url="http://localhost:8181")

# Set user context from auth token
set_user_context("kalyan@company.com", ["analyst", "apac_reader"], "IN")

# This call is unchanged — OPA fires transparently
df = spark.read.parquet("s3://bucket/customers/secured/")
df.show()
# → only rows with _sec_lo bits fully within the permitted mask
# → _sec_lo and _sec_hi columns stripped from result
```

```python
# plugin/opa_plugin.py (core logic)
def install_opa_plugin(spark, opa_url="http://localhost:8181", fail_open=False):
    from pyspark.sql.readwriter import DataFrameReader
    client = OpaClient(opa_url)

    original_parquet = DataFrameReader.parquet

    @wraps(original_parquet)
    def secured_parquet(self, *paths, **options):
        df = original_parquet(self, *paths, **options)
        return _apply_security_filter(df, client, fail_open)

    DataFrameReader.parquet = secured_parquet


def _apply_security_filter(df, opa_client, fail_open):
    if "_sec_lo" not in df.columns:
        return df  # unsecured table, pass through

    permitted_lo, permitted_hi = opa_client.get_permitted_mask(_current_user())

    forbidden_lo = (~permitted_lo) & 0x7FFF_FFFF_FFFF_FFFF
    forbidden_hi = (~permitted_hi) & 0x7FFF_FFFF_FFFF_FFFF

    return df.filter(
        (F.col("_sec_lo").bitwiseAND(F.lit(forbidden_lo)) == 0) &
        (F.col("_sec_hi").bitwiseAND(F.lit(forbidden_hi)) == 0)
    ).drop("_sec_lo", "_sec_hi")
```

The `fail_open=False` default is important: if OPA is unreachable, the filter returns an empty DataFrame rather than unfiltered data. Security failures are closed by default.

---

## What the Prototype Validates

The end-to-end test suite asserts specific behavioral guarantees:

```python
def test_apac_reader_sees_only_apac(spark, secured_parquet):
    set_user_context("analyst@co.com", ["analyst", "apac_reader"])
    df = spark.read.parquet(secured_parquet)
    regions = {r["region"] for r in df.collect()}
    assert regions == {"APAC"}

def test_phi_unauthorized_sees_no_health_records(spark, secured_parquet):
    set_user_context("analyst@co.com", ["analyst", "apac_reader"])
    df = spark.read.parquet(secured_parquet)
    health_rows = [r for r in df.collect() if r.get("health_condition")]
    assert len(health_rows) == 0

def test_phi_authorized_sees_health_records(spark, secured_parquet):
    set_user_context("doctor@co.com", ["analyst", "phi_authorized", "apac_reader"])
    df = spark.read.parquet(secured_parquet)
    health_rows = [r for r in df.collect() if r.get("health_condition")]
    assert len(health_rows) > 0

def test_opa_unreachable_fails_closed(spark, secured_parquet):
    install_opa_plugin(spark, opa_url="http://localhost:9999", fail_open=False)
    set_user_context("analyst@co.com", ["analyst"])
    df = spark.read.parquet(secured_parquet)
    assert df.count() == 0
```

Beyond functional correctness, the architecture validates three structural properties:

**OPA is called exactly once per `spark.read()`.** Add debug logging to `OpaClient.get_permitted_mask` — it fires once per read call, on the driver, regardless of how many partitions Spark scans. Executors never call OPA.

**The bitmap is the only contract between Step 1 and Step 2.** The OPA Rego policy never imports pipeline code. The pipeline never imports Rego. The bit registry is the single shared interface — a stable, versioned schema rather than a security policy.

**Tables without `_sec_lo` columns pass through unchanged.** The plugin is safe to install globally — it has no effect on tables that haven't been through the characterization pipeline.

---

## Why This Is Different From Existing Approaches

| Approach | Enforcement layer | Cross-engine? | OPA called per... | Bypass via direct S3? |
|---|---|---|---|---|
| Apache Ranger | Engine plugin | Partial (per-engine integration) | Query | Yes |
| AWS Lake Formation | Engine + catalog | AWS engines only | Query | Yes |
| Unity Catalog row filters | Engine (Delta only) | No (Iceberg not supported) | Query | Yes |
| Polaris (Iceberg) | Catalog (RBAC only) | Yes | Request | Yes |
| **This approach** | **Parquet file (physical column)** | **Yes — any Parquet reader** | **Once per read(), on driver** | **No — characterization is in the file** |

The last row of that table is the point. A direct `pyarrow.parquet.read_table()` call that reads the physical file will still see the `_sec_lo` column. A reader that doesn't know about the security convention will surface it as a plain integer column. A reader that does — any reader that implements the plugin — will enforce correctly. The characterization is durable in the file, not dependent on a running catalog or security service to exist at read time.

This doesn't mean the approach is immune to a determined adversary who reads raw bytes. What it means is that the security metadata travels with the data. Copying a file to a new bucket doesn't strip the characterization. Changing catalog configurations doesn't alter what the file says about itself.

---

## The Performance Argument

The performance profile is worth stating explicitly, because it's often misunderstood in discussions of row-level security.

**OPA cost**: one HTTP round-trip per `spark.read()`, on the driver. Typically 1–5ms. This cost is paid once regardless of table size or partition count.

**Filter evaluation cost**: one 64-bit AND and one equality comparison per row, executed in the Spark executor's vectorized scan loop. At columnar execution speeds this is effectively free — INT64 bitwise operations are among the cheapest computations a CPU can perform.

**I/O cost**: in this prototype, Spark reads all row groups and applies the filter post-scan. In the production path, this is where the performance pyramid pays off:

```
Iceberg manifest (file-level OR bitmap)
  → skip entire files before any S3 GetObject  ← zero I/O

Parquet row group metadata (row-group-level OR bitmap)
  → skip row groups at file open time           ← minimal I/O

Vectorized column reader (_sec_lo column)
  → filter rows at decode time                  ← minimal CPU
```

Each level stores the OR (union) of all bitmaps beneath it. A file whose every row has `_sec_lo = 0x00000100` (PII only) can be skipped entirely for a user whose permitted mask has the PII bit unset — before the file is opened. This is the same mechanism Parquet uses for min/max pushdown on numeric columns, applied to security characterization.

The prototype doesn't implement the OR bitmap levels — that requires either a custom Parquet writer or Iceberg manifest extension. But it establishes the semantic model that those optimizations build on. Correctness first; physical optimization is independently implementable.

---

## What This Defers

Being honest about what the prototype doesn't yet do:

**Row group metadata bitmaps.** Store the OR of all row bitmaps in Parquet `key_value_metadata`, enabling group-level skip at file open time. Requires a custom Parquet writer or post-write metadata injection.

**Iceberg manifest bitmaps.** Add OR bitmaps to Iceberg manifest entries, enabling file-level skip at scan planning time before any S3 GetObject. Requires either an Iceberg spec extension or a custom manifest writer.

**Scala Catalyst rule injection.** Replace the Python monkey-patch with `SparkSessionExtensions.injectOptimizerRule`. This injects the filter at the Catalyst optimizer level, where Spark can push the `bitwiseAND` predicate into the Parquet statistics scan — closer to true pushdown rather than post-read filtering.

**Schema registry with versioning.** When a new characterization dimension is added (say, `gdpr_special_category`), files written under the old schema need to remain readable. The registry needs a version number, migration tooling, and a contract that new bits default to unset (most restrictive interpretation) when reading old files.

**Characterization accuracy pipeline.** The prototype uses explicit rules. Production requires ML classifiers (AWS Macie, Microsoft Presidio) for PII/PHI detection, confidence scoring, and a human review queue for low-confidence rows. False negatives (failing to set a bit that should be set) are security risks; false positives (setting bits unnecessarily) restrict legitimate access.

None of these are blockers for the prototype's validity. They are independent engineering problems with well-understood solution paths.

---

## Connection to Theory

The architecture is a practical realisation of the Bell-LaPadula confidentiality model (1973), extended with categories.

Bell-LaPadula separates classification level (the sensitivity dimension in the bitmap) from compartments (the regulatory scope, origin, and data type dimensions). A subject can read a document if their clearance level dominates the document's classification *and* they have need-to-know for all of the document's compartments.

The prototype maps this directly: the sensitivity bits are the classification level, the regulatory and origin bits are compartments, and OPA's role-to-dimension grants are the need-to-know assignments. The `(doc_bits & ~permitted_bits) == 0` filter is the dominance check, evaluated at columnar scan speed.

What's new is the physical encoding — giving the classification and compartment assignments first-class representation as a typed column in the storage layer, rather than keeping them only in a catalog or policy store. That encoding is what makes the characterization format-native, durable, and independent of any particular catalog or engine.

---

## The Bigger Implication

The current conversation in the Iceberg ecosystem is focused on extending the REST Catalog protocol to carry row filter and column mask expressions. That's a useful improvement. But it still couples enforcement to the catalog — engines receive expressions from the catalog and are trusted to apply them. Direct reads still bypass it. It still requires every engine to implement the protocol.

The characterization bitmap approach decouples *what the data is* from *what policy says about it*, and gives the former a permanent home in the file. Policy can change, catalogs can be replaced, engines can be swapped — the file still knows what it contains.

That's a different class of guarantee than anything the catalog-centric approaches offer.

---

## Getting Started

The full prototype — characterization pipeline, OPA policy, Spark plugin, and test suite — is available at https://github.com/kbynd/parquet-opa-security.

```bash
# Start OPA
docker-compose up -d

# Characterize sample data
python pipeline/characterize.py data/sample_raw.csv /tmp/secured/customers.parquet

# Inspect what was written
python -c "
import pyarrow.parquet as pq
from registry.characterization import decode
t = pq.read_table('/tmp/secured/customers.parquet')
for row in t.to_pandas().itertuples():
    print(f'{row.name:20s}  {hex(row._sec_lo):18s}  {decode(row._sec_lo, row._sec_hi)}')
"

# Run tests
pytest tests/ -v
```

The test output for an APAC analyst without PHI authorization:
```
PASSED  test_apac_reader_sees_only_apac
PASSED  test_phi_unauthorized_sees_no_health_records
PASSED  test_opa_unreachable_fails_closed
```

And with PHI authorization added to the role set:
```
PASSED  test_phi_authorized_sees_health_records
```

---

## Conclusion

The Iceberg community's admission that there is no easy way to secure lakehouse data across engines reflects a genuine architectural gap, not an implementation shortcoming. The gap exists because every current approach tries to enforce security at the engine or catalog layer — above the data — rather than encoding security-relevant information in the data itself.

The approach described here doesn't solve every lakehouse security problem. It solves a specific one: giving data a durable, format-native characterization that travels with it, so that any reader that understands the convention can enforce access control correctly — and any reader that doesn't will at least surface the characterization columns rather than silently ignoring them.

The two-step separation — characterize at write time, decide at query planning time — is not a clever trick. It's the correct decomposition of what has historically been collapsed into a single, engine-coupled operation. The bitmap is the contract between them.

The prototype is working code. The end-to-end tests pass. The OPA call fires once per read, not once per row. And `spark.read.parquet(path)` is unchanged.

---

*The author is a software consultant specializing in data engineering and booking platforms. The ideas in this article emerged from a design exercise exploring format-native enforcement as an alternative to catalog-coupled lakehouse security.*
