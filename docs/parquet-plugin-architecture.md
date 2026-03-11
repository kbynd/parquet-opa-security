# Formalizing the OPA-Parquet Security Model as a Native Parquet Reader Plugin

## Executive Summary

The OPA-Parquet Security Prototype currently relies on high-level integration points like Spark's `DataFrameReader` monkey-patching and Java wrappers (`SecuredParquetReader`). To achieve true engine-agnosticism and maximize performance, this architecture must be pushed down to the lowest possible layer: **a native Parquet Reader Plugin**.

By integrating the bitmap-based security contract directly into the Parquet columnar read implementation (e.g., Apache Arrow, Parquet-MR), we ensure that **any** system reading the physical bytes—whether it's DuckDB, Trino, Iceberg, PyArrow, or a custom Rust tool—enforces the security policy correctly and efficiently.

This document formalizes the design of this native plugin architecture.

---

## 1. Architectural Goal: Low-Level Pushdown

The current model:
`Engine (Spark) -> DataFrame Interceptor -> Spark Parquet Output -> Bitmap Filter`

The proposed plugin model:
`Engine -> Native Parquet C++ / Java / Rust Library (Plugin Installed) -> Evaluates OPA OR Mask -> Reads Bytes -> Filters Decoded Bitmaps -> Returns Clean Vectors`

### Key Advantages
1. **True Cross-Engine Compatibility:** If Trino, Spark, and DuckDB all use standard Parquet reader libraries (like `parquet-mr` or Apache Arrow), installing the plugin at this layer secures all of them simultaneously.
2. **Pushdown to the I/O Layer:** Row-group skipping based on security metadata happens before any columnar data is decompressed or loaded into memory.
3. **Prevention of End-Runs:** Bypassing catalog-level security (e.g., Unity Catalog, AWS Lake Formation) with direct `pyarrow.parquet.read_table(s3_path)` is no longer a vulnerability. The file parser itself enforces the rules.

---

## 2. Plugin Integration Points (The Lifecycle)

A native Parquet reader plugin must hook into the standard Parquet read lifecycle at three distinct points:

### A. Initialization & Policy Resolution (Split-Time)
When the reader is initialized for a split/file, the plugin must:
1. Identify the user context (passed via environment variables, thread-local storage, or reader configuration properties).
2. Make a single $O(1)$ call to the OPA server to fetch the **Permitted Mask** (`permitted_lo`, `permitted_hi`).
3. Cache this mask for the duration of the read operation.

### B. Row Group Pruning (Metadata Read-Time)
Before reading a Row Group, the Parquet reader parses the footer metadata.
1. The characterization pipeline (Step 1) must be updated to store the **bitwise OR** of all `_sec_lo` and `_sec_hi` values for a row group in the Parquet `key_value_metadata` (e.g., `security.row_group_or_mask_lo`).
2. **Plugin Action:** The plugin intercepts the row group evaluation phase.
3. **Logic:** If `(RowGroup_OR_Mask & ~PermittedMask) != 0` AND there are no rows in the group that *exclusively* contain permitted bits, the group cannot be entirely skipped safely unless we know the minimum set of bits.
    * *Correction for strict BLP Dominance:* The row group metadata should ideally track the *minimum* required clearance, or simply track if the group contains *any* fully permitted rows. A Bloom Filter on the combinations, or simply an `OR` mask of safe subsets, is required.
    * *Simpler implementation:* If the `OR` mask of the entire row group falls within the `PermittedMask`, the entire row group is safe to read without per-row filtering.

### C. Vectorized Column Pruning (Decompression-Time)
When a row group is read, the plugin intercepts the assembly of the columnar vectors:
1. The `_sec_lo` and `_sec_hi` columns are decoded first.
2. A fast, SIMD-optimized bitwise AND operation is applied to generate a boolean selection vector:
   `SelectionVector[i] = ((sec_lo[i] & ~permitted_lo) == 0)`
3. The remaining data columns are read/decompressed.
4. **Plugin Action:** The reader uses the `SelectionVector` to filter the data columns *in-flight*, exactly as it would for a pushed-down SQL `WHERE` clause.
5. `_sec_lo` and `_sec_hi` columns are dropped from the final projected schema returned to the engine.

---

## 3. Implementation Targets

To make this a reality, plugins must be written for the dominant Parquet implementations:

### Target 1: Parquet-MR (Java)
**Used by:** Spark, Trino, Hive, Flink.
**Implementation:**
Implement a custom `FilterPredicate` or extend `ParquetRecordReader`.
Parquet-MR supports pushdown filters. The plugin registers a mandatory filter on `_sec_lo` and `_sec_hi` that is injected into every `ParquetReader.builder()` via Hadoop Configuration properties (`core-site.xml`).

### Target 2: Apache Arrow (C++ / Python / Rust)
**Used by:** DuckDB, PyArrow, Pandas, Polars, DataFusion.
**Implementation:**
Arrow's Parquet reader allows pushing down dataset expressions.
The plugin must hook into `arrow::dataset::ScannerBuilder` or be implemented as a custom `arrow::fs::FileSystem` wrapper that strips unauthorized rows at the `RecordBatch` level before returning them to the execution engine.

---

## 4. Formal Contract Specification

The interface between the application (or engine) and the Parquet Reader Plugin is strictly configuration-based.

**Required Configuration Keys:**
*   `parquet.security.plugin.enabled`: `true`
*   `parquet.security.opa.endpoint`: `https://opa.internal/v1/data/lakehouse/access`
*   `parquet.security.user.context.json`: `{"id": "user@corp.com", "roles": ["analyst"]}`
*   `parquet.security.fail_open`: `false`

**Fail-Safe Guarantee:**
If the plugin is enabled but the `_sec_lo` column is missing from the physical file, the plugin behaves based on a `strict_mode` toggle. In strict mode, it throws an `AccessDeniedException` (assuming the data is uncharacterized and therefore unsafe). In permissive mode, it passes the data through.

---

## 5. Next Steps for Development
1. **Proof of Concept (Parquet-MR):** Create a Hadoop `InputFormat` wrapper or `FilterApi` implementation that injects the bitwise calculation without requiring Spark-level monkey-patching.
2. **Metadata Injection:** Update `pipeline/characterize.py` to calculate the Row Group OR-masks and write them to the Parquet footer using PyArrow.
3. **C++ Arrow Extension:** Write a lightweight C++ extension for PyArrow that enforces the bitwise filter during `read_table`.
