# Security Dimensions Usage Guide

**Date**: March 10, 2026
**Purpose**: Practical guide for using the schema-driven security dimensions model

---

## Overview

This guide shows how to use column metadata to automatically derive security bitmaps for Parquet files. The system reads security annotations from your schema and derives row-level bitmaps based on:

1. **Column metadata** (constant per column): sensitivity, regulatory, purpose, datatype
2. **Row values** (dynamic): geographic scope from actual data values

---

## Quick Start

### 1. Annotate Your Schema

When creating a Parquet file, annotate columns with security metadata:

```java
import org.apache.parquet.schema.*;
import static org.apache.parquet.schema.Types.*;

MessageType schema = Types.buildMessage()
    .required(BINARY).named("customer_id")
    .required(BINARY).named("name")
        .withMetadata("column.name.security.sensitivity", "internal")
        .withMetadata("column.name.security.datatype", "customer_data")
    .required(BINARY).named("email")
        .withMetadata("column.email.security.sensitivity", "internal")
        .withMetadata("column.email.security.regulatory", "pii,gdpr")
        .withMetadata("column.email.security.datatype", "customer_data")
    .required(INT64).named("salary")
        .withMetadata("column.salary.security.sensitivity", "confidential")
        .withMetadata("column.salary.security.regulatory", "pii,financial")
        .withMetadata("column.salary.security.datatype", "employee_data")
    .required(BINARY).named("region")
        .withMetadata("column.region.security.geographic", "value_based")
        .withMetadata("column.region.security.datatype", "customer_data")
    .named("employees");
```

**Note**: Metadata is stored in file-level key-value pairs with format:
```
"column.<column_name>.security.<dimension>" = "<value>"
```

### 2. Derive Security Bitmaps

Use the `BitmapDerivation` class to compute security bitmaps:

```java
import io.parquet.security.dimensions.*;
import java.util.*;

// Parse metadata from schema
Map<String, ColumnSecurityMetadata> columnMetadata =
    ColumnSecurityMetadata.parseFromFileMetadata(schema, fileMetadata);

// For each row, derive bitmap
Map<String, Object> rowValues = new HashMap<>();
rowValues.put("customer_id", "12345");
rowValues.put("name", "Alice");
rowValues.put("email", "alice@example.com");
rowValues.put("salary", 120000L);
rowValues.put("region", "APAC");  // This value determines geographic bit!

BitmapDerivation.SecurityBitmap bitmap =
    BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

System.out.println("_sec_lo: 0x" + Long.toHexString(bitmap.secLo));
System.out.println("_sec_hi: 0x" + Long.toHexString(bitmap.secHi));

// Decode for debugging
System.out.println(BitmapDerivation.describe(bitmap));
```

**Output**:
```
_sec_lo: 0x2011001904
_sec_hi: 0x0
SecurityBitmap{
  _sec_lo: 0x2011001904
  _sec_hi: 0x0
  Sensitivity: [confidential]
  Regulatory: [pii, gdpr, financial]
  Geographic: [apac]
  Purpose: []
  DataType: [customer_data, employee_data]
}
```

---

## Security Dimensions Reference

### Dimension 1: Sensitivity Level (Hierarchical)

**Metadata Key**: `column.<name>.security.sensitivity`

**Values**: `public`, `internal`, `confidential`, `restricted`

**Access Rule**: User can "read down" (confidential user can read public, internal, confidential)

**Example**:
```java
.withMetadata("column.email.security.sensitivity", "internal")
```

**Important**: When multiple columns have different sensitivity levels, the **highest level** is used for the row.

```java
// Row has columns with sensitivity: public, internal, confidential
// Row bitmap will have bit for: confidential (highest)
```

### Dimension 2: Regulatory Scope (Compartments)

**Metadata Key**: `column.<name>.security.regulatory`

**Values** (comma-separated): `pii`, `phi`, `pci`, `financial`, `gdpr`, `export_control`, `legal_privilege`, `trade_secret`

**Access Rule**: User must have **ALL** required scopes

**Example**:
```java
.withMetadata("column.email.security.regulatory", "pii,gdpr")
```

**Accumulation**: All regulatory scopes from all columns are combined:
```java
// email column: pii, gdpr
// salary column: pii, financial
// Row bitmap: pii, gdpr, financial (all accumulated)
```

### Dimension 3: Geographic Scope (Compartments)

**Metadata Key**: `column.<name>.security.geographic`

**Values**:
- Constant: `apac`, `emea`, `amer`, `global`, `us`, `eu`, `cn`, `in`, `uk`, `ca`
- Dynamic: `value_based` (reads from row value)

**Access Rule**: User needs **AT LEAST ONE** matching scope

**Example (Constant)**:
```java
.withMetadata("column.customer_id.security.geographic", "apac,emea")
```

**Example (Value-Based)**:
```java
.withMetadata("column.region.security.geographic", "value_based")

// Row has: region = "APAC"
// Bitmap will have bit 24 (region_apac) set
```

**Use Cases**:
- Constant: Data inherently belongs to specific regions (e.g., EMEA customer records)
- Value-based: Region determined by row data (e.g., `country` or `region` column)

### Dimension 4: Functional Purpose (Purpose Limitation)

**Metadata Key**: `column.<name>.security.purpose`

**Values** (comma-separated): `analytics`, `operations`, `marketing`, `research`, `training`, `audit`, `support`, `development`

**Access Rule**: User needs **AT LEAST ONE** matching purpose

**Example**:
```java
.withMetadata("column.customer_id.security.purpose", "analytics,operations")
```

**Accumulation**: All purposes from all columns are combined.

### Dimension 5: Data Type (Informational)

**Metadata Key**: `column.<name>.security.datatype`

**Values**: `customer_data`, `employee_data`, `financial_data`, `health_data`, `system_logs`

**Access Rule**: No direct access control (informational only)

**Example**:
```java
.withMetadata("column.email.security.datatype", "customer_data")
```

**Purpose**: Helps with classification, routing, data catalog integration.

---

## Complete Examples

### Example 1: Customer Data with Geographic Restrictions

```java
MessageType schema = Types.buildMessage()
    .required(BINARY).named("customer_id")
        .withMetadata("column.customer_id.security.sensitivity", "internal")
        .withMetadata("column.customer_id.security.datatype", "customer_data")
    .required(BINARY).named("email")
        .withMetadata("column.email.security.sensitivity", "internal")
        .withMetadata("column.email.security.regulatory", "pii,gdpr")
        .withMetadata("column.email.security.datatype", "customer_data")
    .required(BINARY).named("region")
        .withMetadata("column.region.security.geographic", "value_based")
    .named("customers");

// Row data
Map<String, Object> row = Map.of(
    "customer_id", "C123",
    "email", "alice@example.com",
    "region", "APAC"
);

BitmapDerivation.SecurityBitmap bitmap =
    BitmapDerivation.deriveRowBitmap(columnMetadata, row);

// Result:
// - Sensitivity: internal (from email column)
// - Regulatory: pii, gdpr (from email column)
// - Geographic: apac (from region VALUE)
// - DataType: customer_data
```

**Who can read this row?**
- User must have `internal` clearance or higher
- User must have both `pii` AND `gdpr` clearances
- User must have `apac` geographic scope (OR `global`)

### Example 2: Employee HR Data

```java
MessageType schema = Types.buildMessage()
    .required(BINARY).named("employee_id")
        .withMetadata("column.employee_id.security.sensitivity", "internal")
        .withMetadata("column.employee_id.security.datatype", "employee_data")
    .required(INT64).named("salary")
        .withMetadata("column.salary.security.sensitivity", "confidential")
        .withMetadata("column.salary.security.regulatory", "pii,financial")
        .withMetadata("column.salary.security.purpose", "operations,audit")
        .withMetadata("column.salary.security.datatype", "employee_data")
    .required(BINARY).named("performance_review")
        .withMetadata("column.performance_review.security.sensitivity", "confidential")
        .withMetadata("column.performance_review.security.regulatory", "pii")
        .withMetadata("column.performance_review.security.purpose", "operations")
        .withMetadata("column.performance_review.security.datatype", "employee_data")
    .named("employees");

// Row data (no value-based geographic)
Map<String, Object> row = Map.of(
    "employee_id", "E456",
    "salary", 120000L,
    "performance_review", "Exceeds expectations"
);

BitmapDerivation.SecurityBitmap bitmap =
    BitmapDerivation.deriveRowBitmap(columnMetadata, row);

// Result:
// - Sensitivity: confidential (highest from salary/performance_review)
// - Regulatory: pii, financial (accumulated from both columns)
// - Purpose: operations, audit (accumulated from both columns)
// - DataType: employee_data
```

**Who can read this row?**
- User must have `confidential` clearance or higher
- User must have `pii` AND `financial` clearances
- User must have `operations` OR `audit` purpose

### Example 3: Healthcare Data

```java
MessageType schema = Types.buildMessage()
    .required(BINARY).named("patient_id")
        .withMetadata("column.patient_id.security.sensitivity", "internal")
        .withMetadata("column.patient_id.security.regulatory", "phi")
        .withMetadata("column.patient_id.security.datatype", "health_data")
    .required(BINARY).named("diagnosis")
        .withMetadata("column.diagnosis.security.sensitivity", "restricted")
        .withMetadata("column.diagnosis.security.regulatory", "phi")
        .withMetadata("column.diagnosis.security.purpose", "operations,research")
        .withMetadata("column.diagnosis.security.datatype", "health_data")
    .required(BINARY).named("country")
        .withMetadata("column.country.security.geographic", "value_based")
    .named("patients");

// Row data
Map<String, Object> row = Map.of(
    "patient_id", "P789",
    "diagnosis", "Type 2 Diabetes",
    "country", "US"
);

BitmapDerivation.SecurityBitmap bitmap =
    BitmapDerivation.deriveRowBitmap(columnMetadata, row);

// Result:
// - Sensitivity: restricted (from diagnosis)
// - Regulatory: phi
// - Geographic: us (from country VALUE)
// - Purpose: operations, research
// - DataType: health_data
```

**Who can read this row?**
- User must have `restricted` clearance (highest level)
- User must have `phi` clearance
- User must have `us` geographic scope (OR `amer`, OR `global`)
- User must have `operations` OR `research` purpose

---

## Integration with Characterization Pipeline

### Step 1: Create Parquet File with Metadata

```java
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;

// Create schema with security metadata (as shown above)
MessageType schema = /* ... */;

// Write file with metadata
Configuration conf = new Configuration();
GroupWriteSupport.setSchema(schema, conf);

// Add file-level metadata
Map<String, String> metadata = new HashMap<>();
metadata.put("column.email.security.sensitivity", "internal");
metadata.put("column.email.security.regulatory", "pii,gdpr");
// ... more metadata

try (ParquetWriter<Group> writer = new ParquetWriter<>(
    filePath,
    new GroupWriteSupport(),
    CompressionCodecName.SNAPPY,
    ParquetWriter.DEFAULT_BLOCK_SIZE,
    ParquetWriter.DEFAULT_PAGE_SIZE,
    ParquetWriter.DEFAULT_PAGE_SIZE,
    true,
    true,
    ParquetWriter.DEFAULT_WRITER_VERSION,
    conf
)) {
    // Write records (WITHOUT _sec_lo/_sec_hi)
    for (Record record : records) {
        Group group = new SimpleGroup(schema);
        group.append("customer_id", record.customerId);
        group.append("email", record.email);
        group.append("region", record.region);
        writer.write(group);
    }
}
```

### Step 2: Run Characterization Pipeline

```java
import io.parquet.security.dimensions.*;
import org.apache.parquet.hadoop.ParquetReader;
import org.apache.parquet.hadoop.ParquetWriter;

// Read existing file
ParquetReader<Group> reader = ParquetReader.builder(
    new GroupReadSupport(),
    new Path("input.parquet")
).build();

MessageType inputSchema = reader.getFooter().getFileMetaData().getSchema();
Map<String, String> fileMetadata = /* extract from footer */;

// Parse column metadata
Map<String, ColumnSecurityMetadata> columnMetadata =
    ColumnSecurityMetadata.parseFromFileMetadata(inputSchema, fileMetadata);

// Create output schema with _sec_lo and _sec_hi
MessageType outputSchema = addSecurityColumns(inputSchema);

// Write secured file
ParquetWriter<Group> writer = /* create writer with outputSchema */;

Group row;
while ((row = reader.read()) != null) {
    // Extract row values
    Map<String, Object> rowValues = extractValues(row);

    // Derive bitmap
    BitmapDerivation.SecurityBitmap bitmap =
        BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

    // Create new row with security columns
    Group securedRow = new SimpleGroup(outputSchema);
    copyFields(row, securedRow);
    securedRow.append("_sec_lo", bitmap.secLo);
    securedRow.append("_sec_hi", bitmap.secHi);

    writer.write(securedRow);
}

reader.close();
writer.close();
```

---

## Validation and Debugging

### Validate Bitmap

```java
BitmapDerivation.SecurityBitmap bitmap = /* derived bitmap */;

List<String> errors = BitmapDerivation.validate(bitmap);
if (!errors.isEmpty()) {
    System.err.println("Validation errors:");
    errors.forEach(System.err::println);
}
```

**Common validation errors**:
- "Multiple sensitivity levels set" - Only one sensitivity bit should be set
- "Reserved bits 4-7 are set" - Reserved space should be zero
- "Schema version mismatch" - Bitmap was created with different schema version

### Decode Bitmap for Debugging

```java
BitmapDerivation.SecurityBitmap bitmap = /* ... */;

// Human-readable description
System.out.println(BitmapDerivation.describe(bitmap));

// Get individual dimensions
Map<String, List<String>> dimensions =
    SecurityDimensionsRegistry.decode(bitmap.secLo, bitmap.secHi);

System.out.println("Sensitivity: " + dimensions.get("sensitivity"));
System.out.println("Regulatory: " + dimensions.get("regulatory"));
System.out.println("Geographic: " + dimensions.get("geographic"));
System.out.println("Purpose: " + dimensions.get("purpose"));
System.out.println("DataType: " + dimensions.get("datatype"));
```

### Inspect Column Contribution

See what each column contributes to the final bitmap:

```java
for (Map.Entry<String, ColumnSecurityMetadata> entry : columnMetadata.entrySet()) {
    String columnName = entry.getKey();
    ColumnSecurityMetadata metadata = entry.getValue();

    Object rowValue = rowValues.get(columnName);

    BitmapDerivation.SecurityBitmap columnBitmap =
        BitmapDerivation.deriveColumnBitmap(metadata, rowValue);

    System.out.println(columnName + ": " +
        BitmapDerivation.describe(columnBitmap));
}
```

---

## Best Practices

### 1. Annotate at File Creation Time

Add security metadata when creating Parquet files, not as a post-processing step.

### 2. Use Value-Based Geographic Sparingly

Only use `value_based` geographic when the region truly varies per row. For static regional data, use constant metadata.

### 3. Document Your Schema

Include a README with your Parquet files explaining the security model:

```markdown
## Security Dimensions

- **Sensitivity**: internal (all customer contact data)
- **Regulatory**: pii, gdpr (email addresses subject to GDPR)
- **Geographic**: value_based (region column contains APAC, EMEA, AMER)
- **Purpose**: analytics, operations (for BI dashboards and ops teams)
```

### 4. Test Your Bitmaps

Always validate bitmaps and test with sample users:

```java
// Test: Can APAC analyst read this row?
UserContext apacAnalyst = new UserContext(
    "analyst@co.com",
    Arrays.asList("analyst", "apac_reader"),
    "IN",
    null
);

PermittedMask mask = policyProvider.getPermittedMask(apacAnalyst);

boolean canRead = ((bitmap.secLo & ~mask.permittedLo) == 0) &&
                  ((bitmap.secHi & ~mask.permittedHi) == 0);

System.out.println("APAC analyst can read: " + canRead);
```

### 5. Version Your Security Schema

When changing bit assignments, increment `SCHEMA_VERSION` and migrate old files.

---

## Troubleshooting

### Problem: Bitmap has multiple sensitivity bits set

**Cause**: Bug in derivation logic or manual bitmap construction

**Solution**: Only one sensitivity bit should be set per row. Use validation:
```java
List<String> errors = BitmapDerivation.validate(bitmap);
```

### Problem: User can't read rows they should access

**Check**:
1. User has correct sensitivity level (can "read down")
2. User has ALL required regulatory scopes
3. User has AT LEAST ONE matching geographic scope
4. User has AT LEAST ONE matching purpose

**Debug**:
```java
// Print user's permitted mask
System.out.println("User permitted: 0x" + Long.toHexString(mask.permittedLo));

// Print row's bitmap
System.out.println("Row bitmap: 0x" + Long.toHexString(bitmap.secLo));

// Check forbidden bits
long forbidden = ~mask.permittedLo;
long conflicts = bitmap.secLo & forbidden;
System.out.println("Conflicts: 0x" + Long.toHexString(conflicts));

// Decode conflicts
Map<String, List<String>> conflictDims =
    SecurityDimensionsRegistry.decode(conflicts, 0L);
System.out.println("User missing: " + conflictDims);
```

### Problem: Value-based geographic not working

**Check**:
1. Column metadata has `"security.geographic": "value_based"`
2. Row value is passed to `deriveRowBitmap(metadata, rowValues)`
3. Value matches expected format (e.g., "APAC", not "apac-region")

**Debug**:
```java
Object regionValue = rowValues.get("region");
System.out.println("Region value: " + regionValue);

long geoBit = SecurityDimensionsRegistry.getGeographicBit(
    regionValue.toString().trim()
);
System.out.println("Geographic bit: 0x" + Long.toHexString(geoBit));
```

---

## Next Steps

1. **OPA Policy Update**: Update your OPA policy to support all 5 dimensions
2. **Characterization Pipeline**: Implement automated pipeline to stamp existing files
3. **Data Catalog Integration**: Export metadata to data catalog for discovery
4. **Monitoring**: Track which dimensions are most commonly used for optimization

---

## Summary

The schema-driven security dimensions model provides:

✅ **Standardized classifications** based on Bell-LaPadula
✅ **Self-documenting** Parquet files with embedded security metadata
✅ **Flexible derivation** combining constant metadata and row values
✅ **Efficient enforcement** using bitmap operations
✅ **Easy debugging** with validation and decode utilities

For implementation details, see:
- `SecurityDimensionsRegistry.java` - Bit definitions
- `ColumnSecurityMetadata.java` - Metadata parser
- `BitmapDerivation.java` - Bitmap derivation logic
- `security-dimensions-model.md` - Complete specification
