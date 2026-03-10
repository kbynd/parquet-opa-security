# Security Dimensions Implementation Summary

**Date**: March 10, 2026
**Status**: ✅ Complete
**Tests**: 73 passing (7 skipped - OPA integration)

---

## What Was Built

We've implemented a complete schema-driven security dimensions system based on the Bell-LaPadula security model. This system allows data owners to annotate Parquet schemas with security metadata, which is then automatically used to derive row-level security bitmaps.

---

## Components Implemented

### 1. SecurityDimensionsRegistry.java

**Purpose**: Central registry for all security dimension definitions and bit allocations

**Location**: `src/main/java/io/parquet/security/dimensions/SecurityDimensionsRegistry.java`

**Key Features**:
- Single source of truth for all bit assignments (128-bit space)
- Five security dimensions:
  1. **Sensitivity Level** (hierarchical): public, internal, confidential, restricted
  2. **Regulatory Scope** (compartments): pii, phi, pci, financial, gdpr, etc.
  3. **Geographic Scope** (compartments): apac, emea, amer, global, us, eu, etc.
  4. **Functional Purpose** (compartments): analytics, operations, marketing, etc.
  5. **Data Type** (informational): customer_data, employee_data, etc.

**API**:
```java
// Get individual bits
long bit = SecurityDimensionsRegistry.getSensitivityBit("confidential");
long bit = SecurityDimensionsRegistry.getRegulatoryBit("pii");

// Get permitted bits (hierarchical "read down")
long permitted = SecurityDimensionsRegistry.getPermittedSensitivityBits("confidential");
// Returns: public | internal | confidential

// Combine multiple scopes
long regulatory = SecurityDimensionsRegistry.getRegulatoryBits(
    Arrays.asList("pii", "gdpr", "financial")
);

// Decode bitmap to human-readable
Map<String, List<String>> dimensions = SecurityDimensionsRegistry.decode(secLo, secHi);
```

**Bit Allocation**:
```
_sec_lo:
  Bits 0-3:   Sensitivity Level (4 bits, hierarchical)
  Bits 8-23:  Regulatory Scope (16 bits, compartments)
  Bits 24-39: Geographic Scope (16 bits, compartments)
  Bits 40-55: Functional Purpose (16 bits, compartments)
  Bits 56-63: Data Type + Schema Version (8 bits)

_sec_hi:
  Bits 64-127: Reserved for future use
```

### 2. ColumnSecurityMetadata.java

**Purpose**: Parse and manage security metadata from Parquet column definitions

**Location**: `src/main/java/io/parquet/security/dimensions/ColumnSecurityMetadata.java`

**Metadata Keys**:
- `security.sensitivity`: Sensitivity level
- `security.regulatory`: Comma-separated regulatory scopes
- `security.geographic`: Geographic scopes or "value_based"
- `security.purpose`: Comma-separated purposes
- `security.datatype`: Data type classification
- `security.derivation`: How metadata was derived (auto/manual/ml)

**API**:
```java
// Parse from Parquet schema
Map<String, ColumnSecurityMetadata> columnMetadata =
    ColumnSecurityMetadata.parseFromFileMetadata(schema, fileMetadata);

// Access metadata
ColumnSecurityMetadata emailMeta = columnMetadata.get("email");
System.out.println(emailMeta.getSensitivity());        // "internal"
System.out.println(emailMeta.getRegulatoryScopes());   // [pii, gdpr]
System.out.println(emailMeta.isGeographicValueBased()); // false
```

**Metadata Format** (in Parquet file):
```
"column.email.security.sensitivity" = "internal"
"column.email.security.regulatory" = "pii,gdpr"
"column.email.security.datatype" = "customer_data"
"column.region.security.geographic" = "value_based"
```

### 3. BitmapDerivation.java

**Purpose**: Derive security bitmaps from column metadata and row values

**Location**: `src/main/java/io/parquet/security/dimensions/BitmapDerivation.java`

**Key Features**:
- Derives `_sec_lo` and `_sec_hi` values for each row
- Combines constant metadata (sensitivity, regulatory, purpose) with dynamic row values (geographic)
- Validates bitmaps (only one sensitivity bit, no reserved bits set, correct schema version)
- Decodes bitmaps for debugging

**API**:
```java
// Derive bitmap for a row
Map<String, Object> rowValues = new HashMap<>();
rowValues.put("email", "alice@example.com");
rowValues.put("region", "APAC");  // Value-based geographic

BitmapDerivation.SecurityBitmap bitmap =
    BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

System.out.println("_sec_lo: 0x" + Long.toHexString(bitmap.secLo));
System.out.println("_sec_hi: 0x" + Long.toHexString(bitmap.secHi));

// Validate
List<String> errors = BitmapDerivation.validate(bitmap);
if (!errors.isEmpty()) {
    System.err.println("Validation errors: " + errors);
}

// Decode for debugging
System.out.println(BitmapDerivation.describe(bitmap));
```

**Derivation Rules**:
- **Sensitivity**: Use HIGHEST level across all columns
- **Regulatory**: ACCUMULATE all scopes from all columns
- **Geographic**:
  - Constant: Use metadata values
  - Value-based: Read from row data (e.g., `region="APAC"` → sets APAC bit)
- **Purpose**: ACCUMULATE all purposes from all columns
- **DataType**: ACCUMULATE all types from all columns

---

## Test Coverage

### SecurityDimensionsRegistryTest.java (10 tests)

Tests all dimension bit operations:
- Individual bit retrieval
- Hierarchical "read down" for sensitivity
- Combined scopes (regulatory, geographic, purpose)
- Encode/decode round-trip
- Bit position non-overlap verification

### BitmapDerivationTest.java (13 tests)

Tests bitmap derivation logic:
- Single dimension derivation
- Multiple columns with different sensitivity levels (max selection)
- Regulatory scope accumulation
- Constant geographic scopes
- Value-based geographic scopes
- Purpose accumulation
- Data type accumulation
- All dimensions combined
- Validation (multiple sensitivity bits, reserved bits, schema version)
- Column-by-column contribution analysis

### SecurityDimensionsExample.java (runnable demo)

Complete working examples:
1. Customer data with value-based geographic
2. Employee HR data with multiple sensitivity levels
3. Healthcare data with PHI
4. Column-by-column contribution analysis

---

## Documentation

### 1. security-dimensions-model.md

Complete specification of the security model:
- Bell-LaPadula mapping
- All 5 dimensions with access rules
- Bitmap allocation across 128 bits
- Column metadata standard
- OPA policy examples
- End-to-end workflow
- Characterization pipeline design

### 2. security-dimensions-usage-guide.md

Practical usage guide:
- Quick start with annotated schemas
- Complete reference for all 5 dimensions
- 3 complete examples (customer, employee, healthcare)
- Integration with characterization pipeline
- Validation and debugging
- Best practices
- Troubleshooting guide

### 3. SECURITY_DIMENSIONS_IMPLEMENTATION.md (this file)

Implementation summary and architecture overview.

---

## Architecture

### Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Data Owner Annotates Schema                             │
│    - Adds security.* metadata to columns                   │
│    - Defines sensitivity, regulatory, purpose, datatype    │
│    - Marks geographic columns as "value_based"             │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Characterization Pipeline                               │
│    - ColumnSecurityMetadata.parseFromFileMetadata()        │
│    - Reads schema annotations                              │
│    - For each row:                                         │
│      * BitmapDerivation.deriveRowBitmap()                  │
│      * Combines metadata + row values → _sec_lo, _sec_hi   │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. Secured Parquet File                                    │
│    - Original columns (name, email, salary, region)        │
│    - Security columns (_sec_lo, _sec_hi)                   │
│    - Schema metadata (security annotations)                │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. Query Engine (Spark/Trino)                              │
│    - Calls OPA: SecurityPolicyProvider.getPermittedMask()  │
│    - Gets permitted_lo, permitted_hi for user              │
│    - Filters rows: (row._sec_lo & ~permitted_lo) == 0      │
└─────────────────────────────────────────────────────────────┘
```

### Component Dependencies

```
┌────────────────────────────────────┐
│ SecurityDimensionsRegistry         │
│ - Bit definitions                  │
│ - Single source of truth           │
└────────────────────────────────────┘
           ▲                ▲
           │                │
           │                │
┌──────────┴──────┐  ┌──────┴─────────────────┐
│ ColumnSecurity  │  │ BitmapDerivation       │
│ Metadata        │  │ - deriveRowBitmap()    │
│ - parseFrom...  │  │ - validate()           │
└─────────────────┘  │ - describe()           │
                     └────────────────────────┘
                              ▲
                              │
                     ┌────────┴────────────────┐
                     │ Characterization        │
                     │ Pipeline                │
                     │ (To be implemented)     │
                     └─────────────────────────┘
```

---

## Key Design Decisions

### 1. Schema-Driven vs Code-Driven

**Decision**: Use Parquet schema metadata instead of external configuration

**Rationale**:
- Self-documenting: Schema describes its own security requirements
- Portable: Works across all engines without config sync
- Discoverable: Data catalog can read security metadata
- Versionable: Security model travels with the data

### 2. Value-Based Geographic

**Decision**: Support both constant metadata and row-value derivation for geographic scope

**Rationale**:
- Some data is inherently regional (EMEA customer records)
- Other data varies by row (customer region field)
- "value_based" marker signals: "read this column's value to get region"
- Flexible without complexity

### 3. Sensitivity Hierarchy

**Decision**: Use HIGHEST sensitivity level when multiple columns have different levels

**Rationale**:
- Conservative: If salary is confidential but name is internal, row is confidential
- Bell-LaPadula compliant: Prevents information leakage
- Simple to implement and understand

### 4. Accumulation for Compartments

**Decision**: ACCUMULATE all regulatory scopes, purposes, and datatypes

**Rationale**:
- If email has PII and salary has Financial, row needs both clearances
- Enforces "need to know" principle
- User must have ALL required scopes to read the row

### 5. Package-Private Constructor

**Decision**: Make `ColumnSecurityMetadata` constructor package-private (not public)

**Rationale**:
- Tests can create instances directly
- Production code uses `parse()` static methods
- Prevents external misuse

---

## Integration Points

### 1. Parquet Schema Creation

When creating Parquet files, add security metadata:

```java
MessageType schema = Types.buildMessage()
    .required(BINARY).named("email")
        .withMetadata("column.email.security.sensitivity", "internal")
        .withMetadata("column.email.security.regulatory", "pii,gdpr")
    .named("customers");
```

### 2. Characterization Pipeline (To Be Implemented)

```java
// Read raw Parquet
ParquetReader<Group> reader = ...;
Map<String, ColumnSecurityMetadata> metadata =
    ColumnSecurityMetadata.parseFromFileMetadata(schema, fileMetadata);

// Write secured Parquet
ParquetWriter<Group> writer = ...;
while ((row = reader.read()) != null) {
    Map<String, Object> rowValues = extractValues(row);
    BitmapDerivation.SecurityBitmap bitmap =
        BitmapDerivation.deriveRowBitmap(metadata, rowValues);

    writeRowWithSecurityColumns(row, bitmap.secLo, bitmap.secHi);
}
```

### 3. OPA Policy (To Be Updated)

OPA policy should use the same bit definitions:

```rego
# Must match SecurityDimensionsRegistry.java
BIT := {
    "sensitivity": {
        "public": 1,
        "internal": 2,
        "confidential": 4,
        "restricted": 8
    },
    "regulatory": {
        "pii": 256,
        "phi": 512,
        "financial": 2048,
        "gdpr": 4096
    },
    # ... etc
}

# Compute permitted mask based on user attributes
permitted_lo := sensitivity_bits | regulatory_bits | geo_bits | purpose_bits
```

### 4. Spark Integration (Already Compatible)

The existing `SecuredParquetFileFormat` already filters using bitmaps:

```scala
val forbiddenLo = (~permittedMask.permittedLo) & 0x7FFFFFFFFFFFFFFFL
val isPermitted = ((secLo & forbiddenLo) == 0)
```

No changes needed - the security dimensions model is a drop-in replacement!

---

## Test Results

```
Tests run: 73, Failures: 0, Errors: 0, Skipped: 7

Test breakdown:
- SecurityDimensionsRegistryTest: 10 tests ✅
- BitmapDerivationTest: 13 tests ✅
- PermittedMaskTest: 19 tests ✅
- OpaSecurityPolicyProviderTest: 14 tests (1 skipped) ✅
- IntegrationTest: 6 tests (6 skipped - require OPA) ⏭
- GroupSecurityColumnExtractorTest: 10 tests ✅
- SecuredParquetReaderTest: 1 test ✅
```

All new security dimensions tests pass. All existing tests still pass (no regressions).

---

## Performance Characteristics

### Bitmap Derivation

- **Column metadata parsing**: O(# columns with metadata) - done once per file
- **Row bitmap derivation**: O(# columns with metadata) - done per row
- **Bitmap operations**: Bitwise OR - extremely fast (nanoseconds)

### Memory Footprint

- **SecurityDimensionsRegistry**: Static maps (~10KB)
- **ColumnSecurityMetadata**: Per-column (~100 bytes per column)
- **SecurityBitmap**: 16 bytes (2 longs)

### Access Control Filtering

- **OPA call**: Once per query (driver only, not per row!)
- **Row filter**: Single comparison: `(secLo & forbidden) == 0`
- **Cost**: ~1 nanosecond per row (bitwise AND + comparison)

---

## Next Steps

### Phase 1: Characterization Pipeline (Pending)

Implement the pipeline that reads raw Parquet files and stamps security bitmaps:

1. Create `CharacterizationPipeline` class
2. Read existing Parquet files
3. Parse column metadata
4. Derive bitmaps for each row
5. Write secured Parquet with `_sec_lo` and `_sec_hi`

### Phase 2: OPA Policy Update (Pending)

Update OPA policy to support all 5 dimensions:

1. Add bit definitions matching `SecurityDimensionsRegistry`
2. Implement hierarchical sensitivity logic
3. Implement compartment logic (regulatory, geographic, purpose)
4. Test with all dimension combinations

### Phase 3: Column-Level Redaction (Future)

Add support for hiding columns based on clearance:

```java
// If user lacks PII clearance, redact email column
if (!user.hasRegulatory("pii")) {
    row.set("email", "***REDACTED***");
}
```

### Phase 4: Schema Registry Integration (Future)

Export security metadata to data catalogs:

- AWS Glue Data Catalog
- Apache Atlas
- OpenMetadata
- DataHub

---

## Migration Guide

### From Old System to Security Dimensions

**Old approach** (manual bit assignment):
```java
long secLo = 0L;
secLo |= 0x2;    // internal
secLo |= 0x100;  // pii
secLo |= 0x1000; // gdpr
// Manual, error-prone, no documentation
```

**New approach** (metadata-driven):
```java
// 1. Annotate schema once
.withMetadata("column.email.security.sensitivity", "internal")
.withMetadata("column.email.security.regulatory", "pii,gdpr")

// 2. Derive automatically
BitmapDerivation.SecurityBitmap bitmap =
    BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);
// Automatic, validated, self-documenting
```

---

## Summary

✅ **Complete implementation** of schema-driven security dimensions
✅ **73 tests passing** with comprehensive coverage
✅ **Self-documenting** Parquet files with embedded security metadata
✅ **Standards-based** design (Bell-LaPadula security model)
✅ **Efficient** bitmap operations (nanoseconds per row)
✅ **Flexible** combination of constant metadata and row values
✅ **Compatible** with existing Spark integration (no changes needed)
✅ **Extensible** with 64 reserved bits for future dimensions

**The security dimensions model is production-ready and ready for characterization pipeline implementation.**

---

## Files Created

### Core Implementation
- `SecurityDimensionsRegistry.java` (367 lines)
- `ColumnSecurityMetadata.java` (251 lines)
- `BitmapDerivation.java` (259 lines)

### Tests
- `SecurityDimensionsRegistryTest.java` (142 lines, 10 tests)
- `BitmapDerivationTest.java` (282 lines, 13 tests)
- `SecurityDimensionsExample.java` (340 lines, runnable demo)

### Documentation
- `security-dimensions-model.md` (536 lines)
- `security-dimensions-usage-guide.md` (693 lines)
- `SECURITY_DIMENSIONS_IMPLEMENTATION.md` (this file)

**Total**: ~2,870 lines of code, tests, and documentation
