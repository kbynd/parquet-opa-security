# Parquet Security Core

Engine-agnostic Parquet security extensions with bitmap-based row filtering.

## Overview

This library provides format-native security for Apache Parquet files using embedded security bitmaps (_sec_lo, _sec_hi columns). It works across all query engines (Spark, DuckDB, Trino, Flink, etc.) without requiring engine-specific plugins.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Application Code (Spark/DuckDB/Trino)                    │
│  - Reads engine-specific configuration                     │
│  - Creates SecurityConfig object                           │
│  - Passes to SecuredParquetReader                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Parquet Security Core (This Library)                     │
│  - SecuredParquetReader (filters rows)                    │
│  - SecurityPolicyProvider (pluggable)                      │
│  - Zero engine dependencies                                 │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### SecurityConfig

Plain data object holding policy provider and user context.

```java
SecurityConfig config = new SecurityConfig(policyProvider, userContext, failOpen);
```

### SecurityPolicyProvider

Pluggable interface for policy evaluation. Implementations:
- `OpaSecurityPolicyProvider` - Calls OPA REST API
- Custom implementations (Azure AD, AWS IAM, hardcoded rules, etc.)

### SecuredParquetReader

Wraps standard Parquet reader and filters rows based on security bitmaps.

```java
SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
    baseReader,
    config,
    new GroupSecurityColumnExtractor()
);
```

## Usage Example

```java
// 1. Read configuration (from Spark, DuckDB, etc.)
String opaUrl = readEngineConfig("security.opa.url");
String userId = readEngineConfig("security.user.id");
List<String> roles = readEngineConfig("security.user.roles");

// 2. Call OPA once to get permitted mask
SecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
UserContext context = new UserContext(userId, roles, null, null);
PermittedMask permittedMask = provider.getPermittedMask(context);

// 3. Create standard Parquet reader
Path file = new Path("/data/customers.parquet");
ParquetReader<Group> baseReader = ParquetReader.builder(new GroupReadSupport(), file)
    .withConf(new Configuration())
    .build();

// 4. Wrap with secured reader (just filtering, no OPA call)
SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
    baseReader,
    permittedMask,
    new GroupSecurityColumnExtractor()
);

// 5. Read filtered records
Group record;
while ((record = reader.read()) != null) {
    // Only permitted records returned
    System.out.println(record);
}

reader.close();
```

## How It Works

### 1. Policy Evaluation (Caller's Responsibility)

The caller (Spark, Trino, etc.) calls the policy provider once to get the permitted bitmap mask for the user:

```java
PermittedMask mask = policyProvider.getPermittedMask(userContext);
// Returns: PermittedMask{permittedLo=0x10103, permittedHi=0x0}
```

The `SecuredParquetReader` then uses this pre-computed mask for filtering - it never calls OPA itself.

### 2. Row Filtering

For each row, the reader:
1. Extracts `_sec_lo` and `_sec_hi` from the record
2. Computes forbidden mask: `~permitted & 0x7FFF_FFFF_FFFF_FFFF`
3. Checks if row has any forbidden bits: `(sec_lo & forbidden_lo) == 0`
4. Returns row if permitted, skips to next if not

```java
long forbiddenLo = (~permittedMask.permittedLo) & 0x7FFF_FFFF_FFFF_FFFFL;
boolean permitted = (secLo & forbiddenLo) == 0;
```

### 3. Unsecured Files

If a file doesn't have `_sec_lo` column, all records pass through (no filtering applied).

## OPA Integration

### OPA Request Format

```json
{
  "input": {
    "user": {
      "id": "analyst@co.com",
      "roles": ["analyst", "apac_reader"],
      "jurisdiction": "IN"
    }
  }
}
```

### OPA Response Format

```json
{
  "result": {
    "permitted_lo": 66819,
    "permitted_hi": 0,
    "allow": true,
    "active_dimensions": ["internal", "pii", "region_apac"]
  }
}
```

### OPA Policy Example

See `policies/lakehouse.rego` in the parent project for a complete OPA policy implementation.

## Configuration Options

### Fail-Open vs Fail-Closed

```java
// Fail-closed (recommended): Deny access on policy evaluation errors
SecurityConfig config = new SecurityConfig(provider, context, false);

// Fail-open: Allow access on policy evaluation errors
SecurityConfig config = new SecurityConfig(provider, context, true);
```

### Custom Policy Providers

Implement `SecurityPolicyProvider` interface:

```java
public class CustomPolicyProvider implements SecurityPolicyProvider {
    @Override
    public PermittedMask getPermittedMask(UserContext user) {
        // Your custom logic here
        return new PermittedMask(permittedLo, permittedHi);
    }
}
```

## Building

```bash
mvn clean package
```

## Testing

```bash
mvn test
```

## Dependencies

- Apache Parquet 1.13.1+
- Java 11+
- SLF4J for logging
- Gson for JSON parsing (OPA responses)

## Integration with Query Engines

See parent project documentation for examples of integrating with:
- Apache Spark
- DuckDB
- Trino
- Apache Flink

## License

Same as parent project
