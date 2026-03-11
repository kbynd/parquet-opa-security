# Write Requirements: Schema-Driven Write Access Control

**Date**: March 11, 2026
**Purpose**: Design schema metadata-driven write access control and auto-classification

---

## Problem Statement

Currently, schema metadata describes **what security properties data has** (sensitivity, regulatory scope, etc.). This is used at:
- **Write time**: Derive bitmaps during characterization
- **Read time**: Filter rows based on user permissions

But we're missing the **write-time access control** piece:
- **Who can write data with certain classifications?**
- **Who can write to columns marked as PII/PHI/Confidential?**
- **How do we prevent unauthorized users from creating highly classified data?**

---

## Bell-LaPadula Write Model

Classic Bell-LaPadula has two rules:

### Simple Security Property (Read Down)
✅ Already implemented
```
User can read data IF: user.clearance >= data.classification
```

### *-Property (Write Up / No Write Down)
❌ Not yet implemented
```
User can write data IF: user.clearance <= data.classification
```

**Why?** Prevents information leakage:
- A user with "Secret" clearance cannot write to "Public" (would leak secrets)
- A user with "Confidential" clearance CAN write to "Secret" (write up is safe)

---

## Use Cases for Write Requirements

### Use Case 1: Prevent Unauthorized Data Creation

**Scenario**: Data analyst without PII clearance tries to create a Parquet file with PII columns.

**Schema annotation**:
```java
.required(BINARY).named("email")
    .withMetadata("column.email.security.sensitivity", "internal")
    .withMetadata("column.email.security.regulatory", "pii,gdpr")
    .withMetadata("column.email.security.write.min_clearance", "pii,gdpr")  // ← NEW
```

**Write-time check**:
```java
UserContext writer = new UserContext("analyst@co.com",
    List.of("analyst"), "US", Map.of());

// Check: Does writer have required clearances?
if (!writer.hasRegulatoryScopes(List.of("pii", "gdpr"))) {
    throw new AccessDeniedException(
        "Writing to 'email' column requires PII and GDPR clearances"
    );
}
```

### Use Case 2: Auto-Classification from Writer Context

**Scenario**: When a user writes data, automatically classify it based on their role/context.

**Schema annotation**:
```java
.required(BINARY).named("notes")
    .withMetadata("column.notes.security.auto_classify", "true")  // ← NEW
    .withMetadata("column.notes.security.min_sensitivity", "internal")
```

**Write-time behavior**:
```java
UserContext writer = new UserContext("analyst@co.com",
    List.of("analyst", "apac_team"), "IN", Map.of());

// Auto-derive classification from writer's attributes
long secLo = 0L;
secLo |= INTERNAL;        // From min_sensitivity
secLo |= REGION_APAC;     // From writer's jurisdiction
secLo |= PURPOSE_ANALYTICS; // From writer's role

// Write row with auto-derived bitmap
```

### Use Case 3: Enforce Minimum Classification

**Scenario**: Salary data MUST always be at least "confidential", even if writer has higher clearance.

**Schema annotation**:
```java
.required(INT64).named("salary")
    .withMetadata("column.salary.security.sensitivity", "confidential")
    .withMetadata("column.salary.security.min_sensitivity", "confidential")  // ← NEW
    .withMetadata("column.salary.security.max_sensitivity", "restricted")    // ← NEW
```

**Write-time validation**:
```java
// User tries to write salary with "internal" classification
BitmapDerivation.deriveRowBitmap(...);

// Validation fails:
// "Column 'salary' requires minimum sensitivity 'confidential', got 'internal'"
```

### Use Case 4: Write-Up Enforcement (Bell-LaPadula)

**Scenario**: User with "internal" clearance cannot write to "public" columns (would leak internal data).

**Schema annotation**:
```java
.required(BINARY).named("description")
    .withMetadata("column.description.security.sensitivity", "public")
    .withMetadata("column.description.security.enforce_write_up", "true")  // ← NEW
```

**Write-time check**:
```java
UserContext writer = new UserContext(...);
int writerLevel = writer.getSensitivityLevel(); // "internal" = level 1

ColumnSecurityMetadata columnMeta = metadata.get("description");
int columnLevel = SecurityDimensionsRegistry.getSensitivityLevel(
    columnMeta.getSensitivity()
); // "public" = level 0

if (writerLevel > columnLevel) {
    throw new AccessDeniedException(
        "Cannot write to 'public' column with 'internal' clearance (write-up violation)"
    );
}
```

### Use Case 5: Mandatory Regulatory Tagging

**Scenario**: System must ensure email columns are ALWAYS tagged as PII.

**Schema validation**:
```java
MessageType schema = readSchema(parquetFile);
Map<String, ColumnSecurityMetadata> metadata =
    ColumnSecurityMetadata.parseFromFileMetadata(schema, fileMetadata);

// Validation rule: Email-like columns MUST have PII
for (Type field : schema.getFields()) {
    if (field.getName().toLowerCase().contains("email")) {
        ColumnSecurityMetadata meta = metadata.get(field.getName());
        if (meta == null || !meta.getRegulatoryScopes().contains("pii")) {
            throw new ValidationException(
                "Column '" + field.getName() + "' appears to be email but lacks PII tag"
            );
        }
    }
}
```

---

## Proposed Schema Metadata Extensions

### Current Metadata (Read-Time)
```
"column.email.security.sensitivity" = "internal"
"column.email.security.regulatory" = "pii,gdpr"
"column.email.security.geographic" = "value_based"
"column.email.security.purpose" = "analytics,operations"
"column.email.security.datatype" = "customer_data"
```

### New Metadata (Write-Time)
```
# Write access control
"column.email.security.write.min_clearance" = "pii,gdpr"
"column.email.security.write.required_roles" = "data_engineer,admin"

# Classification constraints
"column.salary.security.min_sensitivity" = "confidential"
"column.salary.security.max_sensitivity" = "restricted"
"column.salary.security.fixed_regulatory" = "pii,financial"  # Must always have these

# Auto-classification
"column.notes.security.auto_classify" = "true"
"column.notes.security.inherit_from_writer" = "geographic,purpose"

# Bell-LaPadula enforcement
"column.description.security.enforce_write_up" = "true"

# Validation rules
"column.email.security.validate_pattern" = "email"  # Regex or type check
"column.email.security.require_metadata" = "pii"
```

---

## Write Requirements API Design

### 1. WriteRequirements Class

```java
public class WriteRequirements {
    private final String columnName;
    private final List<String> requiredRegulatory;  // Writer must have these
    private final List<String> requiredRoles;
    private final String minSensitivity;  // Minimum classification level
    private final String maxSensitivity;  // Maximum classification level
    private final boolean enforceWriteUp;  // Bell-LaPadula *-property
    private final boolean autoClassify;  // Auto-derive from writer context
    private final List<String> inheritFromWriter;  // Dimensions to inherit

    public static Map<String, WriteRequirements> parseFromSchema(
        MessageType schema,
        Map<String, String> fileMetadata
    ) {
        // Parse "column.*.security.write.*" metadata
    }

    public void validateWriter(UserContext writer) throws AccessDeniedException {
        // Check: Does writer have required clearances?
        if (!writer.hasAllRegulatory(requiredRegulatory)) {
            throw new AccessDeniedException(...);
        }

        // Check: Does writer have required roles?
        if (!writer.hasAnyRole(requiredRoles)) {
            throw new AccessDeniedException(...);
        }

        // Check: Write-up enforcement
        if (enforceWriteUp && writer.getSensitivityLevel() > getColumnLevel()) {
            throw new AccessDeniedException(
                "Cannot write down: writer has higher clearance than column"
            );
        }
    }

    public SecurityBitmap deriveAutoClassification(UserContext writer) {
        if (!autoClassify) {
            return null;
        }

        long secLo = 0L;

        // Inherit writer's attributes
        if (inheritFromWriter.contains("geographic")) {
            secLo |= SecurityDimensionsRegistry.getGeographicBit(
                writer.getJurisdiction()
            );
        }

        if (inheritFromWriter.contains("purpose")) {
            for (String purpose : derivePurposesFromRoles(writer.getRoles())) {
                secLo |= SecurityDimensionsRegistry.getPurposeBit(purpose);
            }
        }

        // Apply minimum sensitivity
        if (minSensitivity != null) {
            secLo |= SecurityDimensionsRegistry.getSensitivityBit(minSensitivity);
        }

        return new SecurityBitmap(secLo, 0L);
    }
}
```

### 2. SecuredParquetWriter Class

```java
public class SecuredParquetWriter<T> implements AutoCloseable {
    private final ParquetWriter<T> delegate;
    private final UserContext writer;
    private final Map<String, WriteRequirements> writeRequirements;
    private final Map<String, ColumnSecurityMetadata> columnMetadata;

    public SecuredParquetWriter(
        Path file,
        WriteSupport<T> writeSupport,
        UserContext writer,
        MessageType schema,
        Map<String, String> fileMetadata
    ) {
        this.delegate = ParquetWriter.builder(writeSupport, file).build();
        this.writer = writer;
        this.writeRequirements = WriteRequirements.parseFromSchema(schema, fileMetadata);
        this.columnMetadata = ColumnSecurityMetadata.parseFromFileMetadata(schema, fileMetadata);

        // Validate writer has permission to write to this schema
        validateWriterAccess();
    }

    private void validateWriterAccess() throws AccessDeniedException {
        for (WriteRequirements req : writeRequirements.values()) {
            req.validateWriter(writer);
        }
    }

    public void write(T record) throws IOException {
        // 1. Extract row values
        Map<String, Object> rowValues = extractValues(record);

        // 2. Derive bitmap from metadata
        SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
            columnMetadata,
            rowValues
        );

        // 3. Auto-classify from writer context
        for (Map.Entry<String, WriteRequirements> entry : writeRequirements.entrySet()) {
            if (entry.getValue().isAutoClassify()) {
                SecurityBitmap auto = entry.getValue().deriveAutoClassification(writer);
                bitmap = bitmap.combine(auto);  // Merge auto-derived bits
            }
        }

        // 4. Validate bitmap meets minimum requirements
        validateBitmap(bitmap);

        // 5. Write row with security columns
        delegate.write(addSecurityColumns(record, bitmap));
    }

    private void validateBitmap(SecurityBitmap bitmap) throws ValidationException {
        for (Map.Entry<String, WriteRequirements> entry : writeRequirements.entrySet()) {
            String columnName = entry.getKey();
            WriteRequirements req = entry.getValue();

            // Check minimum sensitivity
            if (req.getMinSensitivity() != null) {
                int bitmapLevel = extractSensitivityLevel(bitmap);
                int minLevel = SecurityDimensionsRegistry.getSensitivityLevel(
                    req.getMinSensitivity()
                );
                if (bitmapLevel < minLevel) {
                    throw new ValidationException(
                        "Column '" + columnName + "' requires minimum sensitivity '"
                        + req.getMinSensitivity() + "'"
                    );
                }
            }

            // Check maximum sensitivity
            if (req.getMaxSensitivity() != null) {
                // Similar validation
            }

            // Check fixed regulatory scopes
            if (!req.getFixedRegulatory().isEmpty()) {
                // Ensure bitmap has all required regulatory bits
            }
        }
    }

    @Override
    public void close() throws IOException {
        delegate.close();
    }
}
```

### 3. Usage Example

```java
// Define schema with write requirements
MessageType schema = Types.buildMessage()
    .required(BINARY).named("email")
        .withMetadata("column.email.security.sensitivity", "internal")
        .withMetadata("column.email.security.regulatory", "pii,gdpr")
        .withMetadata("column.email.security.write.min_clearance", "pii,gdpr")  // ← Write control
    .required(INT64).named("salary")
        .withMetadata("column.salary.security.sensitivity", "confidential")
        .withMetadata("column.salary.security.min_sensitivity", "confidential")  // ← Enforce minimum
        .withMetadata("column.salary.security.enforce_write_up", "true")         // ← Write-up enforcement
    .required(BINARY).named("notes")
        .withMetadata("column.notes.security.auto_classify", "true")             // ← Auto-classify
        .withMetadata("column.notes.security.inherit_from_writer", "geographic,purpose")
    .named("employees");

// Create writer with user context
UserContext writer = new UserContext(
    "analyst@co.com",
    List.of("analyst", "apac_team"),
    "IN",
    Map.of("regulatory_clearances", List.of("pii", "gdpr"))
);

Map<String, String> fileMetadata = extractMetadata(schema);

try (SecuredParquetWriter<Group> writer = new SecuredParquetWriter<>(
    Path.of("/tmp/secured/employees.parquet"),
    new GroupWriteSupport(),
    writer,
    schema,
    fileMetadata
)) {
    // This will succeed - writer has PII/GDPR clearances
    Group row1 = createRow("alice@example.com", 120000L, "Customer inquiry");
    writer.write(row1);

    // This will FAIL - salary requires confidential, writer only has internal
    Group row2 = createRow("bob@example.com", 50000L, "Low salary");
    writer.write(row2);  // AccessDeniedException

} catch (AccessDeniedException e) {
    System.err.println("Write denied: " + e.getMessage());
}
```

---

## Benefits of This Approach

### 1. **Self-Enforcing Schemas**
- Schema declares its own write requirements
- No external ACL configuration needed
- Schema = security policy

### 2. **Defense in Depth**
- Write-time: Prevent unauthorized data creation
- Read-time: Filter unauthorized data access
- Two layers of protection

### 3. **Auto-Classification**
- Reduces manual annotation burden
- Consistent classification based on writer context
- "Analyst in APAC writes → auto-tagged as APAC + Analytics"

### 4. **Bell-LaPadula Compliant**
- Prevents information leakage via write-down
- Enforces "need to know" at write time
- Formal security model

### 5. **Auditability**
- Every write is validated and logged
- Schema metadata documents who can write what
- Compliance-friendly

---

## Implementation Phases

### Phase 1: Write Requirements Parser
- Extend `ColumnSecurityMetadata` to parse `security.write.*` metadata
- Create `WriteRequirements` class
- Unit tests for parsing and validation

### Phase 2: SecuredParquetWriter
- Create wrapper around `ParquetWriter`
- Implement write-time validation
- Auto-classification from writer context

### Phase 3: OPA Integration
- OPA policy returns write permissions (not just read)
- Check: `{"action": "write", "resource": "employees.parquet", "column": "email"}`
- Returns: `{"allowed": true, "required_clearances": ["pii", "gdpr"]}`

### Phase 4: Schema Validation Tool
- CLI tool to validate schemas
- Check: Email columns have PII tags
- Check: Salary columns are confidential
- Check: Write requirements are consistent

---

## Open Questions

### 1. Should write-up be mandatory or opt-in?
- **Option A**: Always enforce (strict Bell-LaPadula)
- **Option B**: Opt-in via `enforce_write_up=true` metadata
- **Recommendation**: Opt-in (more flexible)

### 2. How to handle schema evolution?
- What if column changes from "internal" to "confidential"?
- Can we read old files with new schema?
- **Recommendation**: Schema version in `_sec_lo` bits 61-63

### 3. Should auto-classification be all-or-nothing?
- Can some columns auto-classify while others use metadata?
- **Recommendation**: Per-column control via `auto_classify` flag

### 4. How to handle auditing?
- Should auditing be mandatory or optional?
- **Decision**: Fully optional via pluggable interface
- Default: No-op (silent)
- Users can plug in: File logger, SIEM, metrics, etc.

---

## Optional Audit Plugin Architecture

### Design Principle
**Auditing is completely optional** - users can run with no auditing (zero overhead) or plug in their own audit handler.

### 1. Audit Event Interface

```java
public interface WriteAuditEvent {
    String getUserId();
    String getFilePath();
    String getColumnName();
    String getAction();  // "write_allowed", "write_denied", "validation_failed"
    String getReason();  // Details if denied
    long getTimestamp();
    Map<String, String> getMetadata();  // Additional context
}

public interface WriteAuditHandler {
    /**
     * Handle a write audit event.
     * Implementation can log to file, send to SIEM, record metrics, etc.
     *
     * @param event The audit event
     */
    void onWriteEvent(WriteAuditEvent event);

    /**
     * Called when writer is closed (optional flush/cleanup)
     */
    default void close() {}
}
```

### 2. Built-in Handlers (Optional)

```java
// No-op (default) - zero overhead
public class NoOpAuditHandler implements WriteAuditHandler {
    @Override
    public void onWriteEvent(WriteAuditEvent event) {
        // Do nothing - zero overhead
    }
}

// Simple file logger (optional)
public class FileAuditHandler implements WriteAuditHandler {
    private final BufferedWriter writer;

    public FileAuditHandler(Path auditLog) throws IOException {
        this.writer = Files.newBufferedWriter(auditLog, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    @Override
    public void onWriteEvent(WriteAuditEvent event) {
        try {
            writer.write(String.format("[%s] %s - %s: %s - %s%n",
                Instant.ofEpochMilli(event.getTimestamp()),
                event.getAction(),
                event.getUserId(),
                event.getFilePath(),
                event.getReason()
            ));
        } catch (IOException e) {
            // Log error but don't fail the write
        }
    }

    @Override
    public void close() {
        try {
            writer.close();
        } catch (IOException ignored) {}
    }
}

// SLF4J logger (optional)
public class Slf4jAuditHandler implements WriteAuditHandler {
    private static final Logger logger = LoggerFactory.getLogger(Slf4jAuditHandler.class);

    @Override
    public void onWriteEvent(WriteAuditEvent event) {
        if ("write_denied".equals(event.getAction())) {
            logger.warn("Write denied - user={}, file={}, column={}, reason={}",
                event.getUserId(), event.getFilePath(), event.getColumnName(), event.getReason());
        } else if ("write_allowed".equals(event.getAction())) {
            logger.debug("Write allowed - user={}, file={}, column={}",
                event.getUserId(), event.getFilePath(), event.getColumnName());
        }
    }
}
```

### 3. SecuredParquetWriter with Optional Auditing

```java
public class SecuredParquetWriter<T> implements AutoCloseable {
    private final ParquetWriter<T> delegate;
    private final UserContext writer;
    private final WriteAuditHandler auditHandler;  // Optional

    // Constructor with no auditing (default)
    public SecuredParquetWriter(
        Path file,
        WriteSupport<T> writeSupport,
        UserContext writer,
        MessageType schema,
        Map<String, String> fileMetadata
    ) {
        this(file, writeSupport, writer, schema, fileMetadata, new NoOpAuditHandler());
    }

    // Constructor with custom audit handler
    public SecuredParquetWriter(
        Path file,
        WriteSupport<T> writeSupport,
        UserContext writer,
        MessageType schema,
        Map<String, String> fileMetadata,
        WriteAuditHandler auditHandler  // User-provided
    ) {
        this.delegate = ParquetWriter.builder(writeSupport, file).build();
        this.writer = writer;
        this.auditHandler = auditHandler != null ? auditHandler : new NoOpAuditHandler();
        this.writeRequirements = WriteRequirements.parseFromSchema(schema, fileMetadata);

        try {
            validateWriterAccess();
        } catch (AccessDeniedException e) {
            // Audit the denial
            auditHandler.onWriteEvent(new WriteAuditEventImpl(
                writer.getUserId(),
                file.toString(),
                null,  // No specific column
                "schema_access_denied",
                e.getMessage(),
                System.currentTimeMillis()
            ));
            throw e;
        }
    }

    public void write(T record) throws IOException {
        try {
            // ... existing write logic ...

            // Audit successful write (if handler is not no-op)
            auditHandler.onWriteEvent(new WriteAuditEventImpl(
                writer.getUserId(),
                file.toString(),
                null,
                "write_allowed",
                "Row written successfully",
                System.currentTimeMillis()
            ));

            delegate.write(addSecurityColumns(record, bitmap));

        } catch (AccessDeniedException e) {
            // Audit the denial
            auditHandler.onWriteEvent(new WriteAuditEventImpl(
                writer.getUserId(),
                file.toString(),
                extractColumnName(e),
                "write_denied",
                e.getMessage(),
                System.currentTimeMillis()
            ));
            throw e;
        } catch (ValidationException e) {
            // Audit validation failure
            auditHandler.onWriteEvent(new WriteAuditEventImpl(
                writer.getUserId(),
                file.toString(),
                extractColumnName(e),
                "validation_failed",
                e.getMessage(),
                System.currentTimeMillis()
            ));
            throw e;
        }
    }

    @Override
    public void close() throws IOException {
        try {
            delegate.close();
        } finally {
            auditHandler.close();
        }
    }
}
```

### 4. Usage Examples

**No auditing (default - zero overhead)**:
```java
try (SecuredParquetWriter<Group> writer = new SecuredParquetWriter<>(
    path, writeSupport, userContext, schema, metadata
    // No audit handler - uses NoOpAuditHandler
)) {
    writer.write(row);
}
```

**With file auditing**:
```java
try (SecuredParquetWriter<Group> writer = new SecuredParquetWriter<>(
    path,
    writeSupport,
    userContext,
    schema,
    metadata,
    new FileAuditHandler(Paths.get("/var/log/parquet-security/audit.log"))
)) {
    writer.write(row);
}
```

**With custom SIEM integration**:
```java
public class SplunkAuditHandler implements WriteAuditHandler {
    private final SplunkClient splunk;

    @Override
    public void onWriteEvent(WriteAuditEvent event) {
        splunk.sendEvent(Map.of(
            "source", "parquet-security",
            "event_type", event.getAction(),
            "user", event.getUserId(),
            "file", event.getFilePath(),
            "reason", event.getReason()
        ));
    }
}

try (SecuredParquetWriter<Group> writer = new SecuredParquetWriter<>(
    path, writeSupport, userContext, schema, metadata,
    new SplunkAuditHandler(splunkClient)  // Custom integration
)) {
    writer.write(row);
}
```

**With metrics (Prometheus/Micrometer)**:
```java
public class MetricsAuditHandler implements WriteAuditHandler {
    private final Counter writesAllowed;
    private final Counter writesDenied;

    public MetricsAuditHandler(MeterRegistry registry) {
        this.writesAllowed = registry.counter("parquet.writes.allowed");
        this.writesDenied = registry.counter("parquet.writes.denied");
    }

    @Override
    public void onWriteEvent(WriteAuditEvent event) {
        if ("write_allowed".equals(event.getAction())) {
            writesAllowed.increment();
        } else if ("write_denied".equals(event.getAction())) {
            writesDenied.increment();
        }
    }
}
```

### 5. Configuration-Based Selection

For frameworks that use configuration (Spark, Trino):

```properties
# Optional audit handler configuration
parquet.security.audit.enabled=true
parquet.security.audit.handler=io.parquet.security.audit.FileAuditHandler
parquet.security.audit.file=/var/log/parquet-security/audit.log

# Or disabled (default)
parquet.security.audit.enabled=false
```

```java
public static WriteAuditHandler createAuditHandler(Configuration conf) {
    if (!conf.getBoolean("parquet.security.audit.enabled", false)) {
        return new NoOpAuditHandler();  // Disabled
    }

    String handlerClass = conf.get("parquet.security.audit.handler");
    if (handlerClass == null) {
        return new NoOpAuditHandler();
    }

    try {
        // Instantiate via reflection
        return (WriteAuditHandler) Class.forName(handlerClass)
            .getConstructor(Configuration.class)
            .newInstance(conf);
    } catch (Exception e) {
        logger.warn("Failed to create audit handler, using no-op", e);
        return new NoOpAuditHandler();
    }
}
```

### 6. Performance Considerations

| Handler | Overhead | Use Case |
|---------|----------|----------|
| `NoOpAuditHandler` (default) | **Zero** - JIT eliminates | Production (no auditing) |
| `Slf4jAuditHandler` | Minimal - async logging | Development/debugging |
| `FileAuditHandler` | Low - buffered writes | Simple file-based audit |
| `MetricsAuditHandler` | Minimal - counter increment | Observability/monitoring |
| `SplunkAuditHandler` | Medium - network call | Compliance/SIEM |

**Default is zero overhead** - users opt into auditing only when needed.

---

## Next Steps

1. **Feedback**: Is this the direction you want?
2. **Implement WriteRequirements parser**
3. **Create SecuredParquetWriter prototype**
4. **Write integration tests**
5. **Update documentation**

---

## Summary

Schema metadata can drive **both read AND write access control**:

**Read-time** (already implemented):
- Filter rows based on user permissions
- `(row._sec_lo & ~permitted) == 0`

**Write-time** (proposed):
- Validate writer has required clearances
- Enforce minimum/maximum classifications
- Auto-classify from writer context
- Prevent write-down (Bell-LaPadula)

This creates a **self-enforcing, self-documenting security model** where the schema is the policy.
