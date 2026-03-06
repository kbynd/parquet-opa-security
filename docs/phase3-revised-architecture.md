# Phase 3: Parquet Reader/Writer Extensions - Revised Architecture

## Architectural Correction

**Problem Identified**: The initial proposal mixed Spark-specific code inside the Parquet reader, violating the engine-agnostic principle.

**Solution**: Configuration-driven approach - no adapters needed:

```
┌─────────────────────────────────────────────────────────────┐
│  Application Code (Spark/Trino/Flink/DuckDB)              │
│  - Reads engine-specific configuration                     │
│  - Translates to SecurityConfig object                     │
│  - Passes config to SecuredParquetReader                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Parquet Security Layer (Engine-Agnostic)                 │
│  - SecuredParquetReader/Writer (accepts config)           │
│  - SecurityConfig (policy provider + user context)        │
│  - SecurityPolicyProvider interface                        │
│  - Zero dependencies on any query engine                   │
└─────────────────────────────────────────────────────────────┘
```

**No adapter layer needed** - application code directly instantiates the reader with config.

## Revised Component Structure

### 1. Engine-Agnostic Parquet Layer

**File**: `parquet-security-core/src/main/java/io/parquet/security/SecurityConfig.java`

```java
package io.parquet.security;

/**
 * Configuration for secured Parquet reading/writing.
 * Engine code creates this and passes to SecuredParquetReader.
 */
public class SecurityConfig {
    private final SecurityPolicyProvider policyProvider;
    private final UserContext userContext;
    private final boolean failOpen;

    public SecurityConfig(
        SecurityPolicyProvider policyProvider,
        UserContext userContext,
        boolean failOpen
    ) {
        this.policyProvider = policyProvider;
        this.userContext = userContext;
        this.failOpen = failOpen;
    }

    public SecurityPolicyProvider getPolicyProvider() { return policyProvider; }
    public UserContext getUserContext() { return userContext; }
    public boolean isFailOpen() { return failOpen; }
}
```

**File**: `parquet-security-core/src/main/java/io/parquet/security/SecuredParquetReader.java`

```java
package io.parquet.security;

import org.apache.parquet.hadoop.ParquetReader;
import org.apache.parquet.hadoop.api.ReadSupport;

/**
 * Engine-agnostic secured Parquet reader.
 * NO dependencies on Spark, Trino, Flink, or any query engine.
 *
 * Application code:
 *   1. Reads its own configuration (Spark conf, Trino session, etc.)
 *   2. Creates SecurityConfig object
 *   3. Passes config to this reader
 */
public class SecuredParquetReader<T> extends ParquetReader<T> {

    private final SecurityConfig securityConfig;
    private PermittedMask permittedMask;

    /**
     * @param readSupport - Standard Parquet read support
     * @param securityConfig - Security configuration (policy provider + user context)
     */
    protected SecuredParquetReader(
        ReadSupport<T> readSupport,
        SecurityConfig securityConfig
    ) throws IOException {
        super(readSupport);
        this.securityConfig = securityConfig;

        // Fetch permitted mask once (OPA called once per reader)
        this.permittedMask = securityConfig.getPolicyProvider()
            .getPermittedMask(securityConfig.getUserContext());
    }

    @Override
    public T read() throws IOException {
        T record = super.read();
        if (record == null) return null;

        // Apply security filtering
        long secLo = extractSecLo(record);
        long secHi = extractSecHi(record);

        if (!isPermitted(secLo, secHi)) {
            return read(); // Skip this record, read next
        }

        return record;
    }

    private boolean isPermitted(long secLo, long secHi) {
        long forbiddenLo = (~permittedMask.permittedLo) & 0x7FFF_FFFF_FFFF_FFFFL;
        long forbiddenHi = (~permittedMask.permittedHi) & 0x7FFF_FFFF_FFFF_FFFFL;

        return ((secLo & forbiddenLo) == 0) && ((secHi & forbiddenHi) == 0);
    }

    private long extractSecLo(T record) {
        // Extract _sec_lo column from record
        // Implementation depends on record type (Avro, Parquet GenericRecord, etc.)
        ...
    }

    private long extractSecHi(T record) {
        // Extract _sec_hi column from record
        ...
    }
}
```

**File**: `parquet-security-core/src/main/java/io/parquet/security/SecurityPolicyProvider.java`

```java
package io.parquet.security;

/**
 * Pluggable interface for security policy evaluation.
 * Implementations: OPA, custom policy engines, hardcoded rules, etc.
 */
public interface SecurityPolicyProvider {

    /**
     * Get permitted bitmap mask for a user.
     *
     * @param user - User context
     * @return Bitmap mask of permitted dimensions
     * @throws SecurityException if policy evaluation fails and fail_open=false
     */
    PermittedMask getPermittedMask(UserContext user) throws SecurityException;
}

/**
 * Result from policy provider.
 */
public class PermittedMask {
    public final long permittedLo;
    public final long permittedHi;

    public PermittedMask(long permittedLo, long permittedHi) {
        this.permittedLo = permittedLo;
        this.permittedHi = permittedHi;
    }
}
```

**File**: `parquet-security-core/src/main/java/io/parquet/security/UserContext.java`

```java
package io.parquet.security;

import java.util.List;
import java.util.Map;

/**
 * User identity and attributes.
 * Engine-agnostic representation.
 */
public class UserContext {
    private final String userId;
    private final List<String> roles;
    private final String jurisdiction;
    private final Map<String, String> attributes;

    public UserContext(
        String userId,
        List<String> roles,
        String jurisdiction,
        Map<String, String> attributes
    ) {
        this.userId = userId;
        this.roles = roles;
        this.jurisdiction = jurisdiction;
        this.attributes = attributes;
    }

    // Getters...
}
```

### 2. OPA Implementation (Still Engine-Agnostic)

**File**: `parquet-security-opa/src/main/java/io/parquet/security/opa/OpaSecurityPolicyProvider.java`

```java
package io.parquet.security.opa;

import io.parquet.security.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * OPA implementation of SecurityPolicyProvider.
 * Still engine-agnostic - just calls OPA REST API.
 */
public class OpaSecurityPolicyProvider implements SecurityPolicyProvider {

    private final String opaUrl;
    private final boolean failOpen;
    private final HttpClient httpClient;

    public OpaSecurityPolicyProvider(String opaUrl, boolean failOpen) {
        this.opaUrl = opaUrl;
        this.failOpen = failOpen;
        this.httpClient = HttpClient.newHttpClient();
    }

    @Override
    public PermittedMask getPermittedMask(UserContext user) throws SecurityException {
        try {
            // Build OPA request
            String requestBody = buildOpaRequest(user);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(opaUrl + "/v1/data/lakehouse/access/result"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                if (failOpen) {
                    return new PermittedMask(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL);
                } else {
                    throw new SecurityException("OPA request failed: " + response.statusCode());
                }
            }

            // Parse response
            return parseOpaResponse(response.body());

        } catch (Exception e) {
            if (failOpen) {
                return new PermittedMask(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL);
            } else {
                throw new SecurityException("OPA evaluation failed", e);
            }
        }
    }

    private String buildOpaRequest(UserContext user) {
        // JSON building logic
        return String.format(
            "{\"input\": {\"user\": {\"id\": \"%s\", \"roles\": %s, \"jurisdiction\": \"%s\"}}}",
            user.getUserId(),
            toJsonArray(user.getRoles()),
            user.getJurisdiction()
        );
    }

    private PermittedMask parseOpaResponse(String json) {
        // JSON parsing logic
        // Extract result.permitted_lo and result.permitted_hi
        ...
    }
}
```

### 3. Usage in Spark (Application Code)

**Example: Spark application reads its config and passes to reader**

```scala
import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import io.parquet.security._
import io.parquet.security.opa.OpaSecurityPolicyProvider

// Spark application code
val sparkSession: SparkSession = ...

// 1. Read Spark-specific configuration
val opaUrl = sparkSession.conf.get("spark.security.opa.url", "http://localhost:8181")
val userId = sparkSession.conf.get("spark.security.user.id")
val rolesStr = sparkSession.conf.get("spark.security.user.roles")
val jurisdiction = sparkSession.conf.getOption("spark.security.user.jurisdiction").orNull
val failOpen = sparkSession.conf.getBoolean("spark.security.fail_open", false)

val roles = rolesStr.split(",").toList.asJava

// 2. Create SecurityConfig object
val policyProvider = new OpaSecurityPolicyProvider(opaUrl, failOpen)
val userContext = new UserContext(userId, roles, jurisdiction, null)
val securityConfig = new SecurityConfig(policyProvider, userContext, failOpen)

// 3. Pass config to SecuredParquetReader
val reader = new SecuredParquetReader(readSupport, securityConfig)
val records = reader.read()
```

**For transparent integration, override Spark's Parquet reading**:

```scala
package io.parquet.security.spark

import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat
import org.apache.spark.sql.sources.Filter
import org.apache.spark.sql.types.StructType
import io.parquet.security._
import io.parquet.security.opa.OpaSecurityPolicyProvider

/**
 * Spark-aware Parquet format that reads Spark config and applies security.
 * This is NOT an "adapter" - it's just Spark application code that
 * knows how to read Spark's configuration.
 */
class SecuredParquetFileFormat extends ParquetFileFormat {

  override def buildReaderWithPartitionValues(
      sparkSession: SparkSession,
      dataSchema: StructType,
      partitionSchema: StructType,
      requiredSchema: StructType,
      filters: Seq[Filter],
      options: Map[String, String],
      hadoopConf: Configuration
  ): PartitionedFile => Iterator[InternalRow] = {

    // Read Spark configuration
    val opaUrl = sparkSession.conf.get("spark.security.opa.url", "http://localhost:8181")
    val userId = sparkSession.conf.get("spark.security.user.id")
    val rolesStr = sparkSession.conf.get("spark.security.user.roles")
    val jurisdiction = sparkSession.conf.getOption("spark.security.user.jurisdiction").orNull
    val failOpen = sparkSession.conf.getBoolean("spark.security.fail_open", false)

    // Create SecurityConfig
    val policyProvider = new OpaSecurityPolicyProvider(opaUrl, failOpen)
    val userContext = new UserContext(userId, rolesStr.split(",").toList.asJava, jurisdiction, null)
    val securityConfig = new SecurityConfig(policyProvider, userContext, failOpen)

    // Fetch permitted mask once (OPA called once per spark.read())
    val permittedMask = policyProvider.getPermittedMask(userContext)

    // Get base reader
    val baseReader = super.buildReaderWithPartitionValues(
      sparkSession, dataSchema, partitionSchema, requiredSchema, filters, options, hadoopConf
    )

    // Wrap with security filtering
    (file: PartitionedFile) => {
      val baseIterator = baseReader(file)

      // Find _sec_lo and _sec_hi column positions
      val secLoIdx = dataSchema.fieldIndex("_sec_lo")
      val secHiIdx = dataSchema.fieldIndex("_sec_hi")

      // Apply filtering
      baseIterator.filter { row =>
        val secLo = row.getLong(secLoIdx)
        val secHi = row.getLong(secHiIdx)

        val forbiddenLo = (~permittedMask.permittedLo) & 0x7FFF_FFFF_FFFF_FFFFL
        val forbiddenHi = (~permittedMask.permittedHi) & 0x7FFF_FFFF_FFFF_FFFFL

        ((secLo & forbiddenLo) == 0) && ((secHi & forbiddenHi) == 0)
      }
    }
  }
}
```

**Register as default Parquet reader**:

```python
from pyspark.sql import SparkSession

spark = SparkSession.builder \
    .master('local[2]') \
    .appName('secured-demo') \
    .config('spark.sql.sources.default', 'secured-parquet') \
    .config('spark.security.opa.url', 'http://localhost:8181') \
    .config('spark.security.user.id', 'analyst@co.com') \
    .config('spark.security.user.roles', 'analyst,apac_reader') \
    .config('spark.security.user.jurisdiction', 'IN') \
    .config('spark.security.fail_open', 'false') \
    .getOrCreate()

# Completely transparent - caller unchanged
df = spark.read.parquet('/tmp/secured/customers.parquet')
df.show()
```

### 4. Usage in Trino (Application Code)

**Example: Trino application reads its config and passes to reader**

```java
package io.parquet.security.trino;

import io.trino.spi.connector.ConnectorPageSource;
import io.trino.spi.connector.ConnectorSession;
import io.parquet.security.*;
import io.parquet.security.opa.OpaSecurityPolicyProvider;

/**
 * Trino-aware page source that reads Trino session properties and applies security.
 * This is NOT an "adapter" - it's just Trino application code that
 * knows how to read Trino's session properties.
 */
public class SecuredParquetPageSource implements ConnectorPageSource {

    private final ConnectorPageSource delegate;
    private final PermittedMask permittedMask;
    private final int secLoIndex;
    private final int secHiIndex;

    public SecuredParquetPageSource(
        ConnectorPageSource delegate,
        ConnectorSession session,
        List<HiveColumnHandle> columns
    ) {
        this.delegate = delegate;

        // 1. Read Trino-specific configuration
        String opaUrl = session.getProperty("security.opa.url", String.class);
        String userId = session.getUser();
        List<String> roles = new ArrayList<>(session.getGroups());
        String jurisdiction = session.getProperty("security.jurisdiction", String.class);
        boolean failOpen = session.getProperty("security.fail_open", Boolean.class);

        // 2. Create SecurityConfig
        SecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(opaUrl, failOpen);
        UserContext userContext = new UserContext(userId, roles, jurisdiction, null);

        // 3. Fetch permitted mask once (OPA called once per query)
        this.permittedMask = policyProvider.getPermittedMask(userContext);

        // Find _sec_lo and _sec_hi column positions
        this.secLoIndex = findColumnIndex(columns, "_sec_lo");
        this.secHiIndex = findColumnIndex(columns, "_sec_hi");
    }

    @Override
    public Page getNextPage() {
        Page page = delegate.getNextPage();
        if (page == null) return null;

        // Apply security filtering
        return filterPage(page);
    }

    private Page filterPage(Page page) {
        Block secLoBlock = page.getBlock(secLoIndex);
        Block secHiBlock = page.getBlock(secHiIndex);

        int[] positions = new int[page.getPositionCount()];
        int outputPositions = 0;

        long forbiddenLo = (~permittedMask.permittedLo) & 0x7FFF_FFFF_FFFF_FFFFL;
        long forbiddenHi = (~permittedMask.permittedHi) & 0x7FFF_FFFF_FFFF_FFFFL;

        for (int i = 0; i < page.getPositionCount(); i++) {
            long secLo = secLoBlock.getLong(i, 0);
            long secHi = secHiBlock.getLong(i, 0);

            if (((secLo & forbiddenLo) == 0) && ((secHi & forbiddenHi) == 0)) {
                positions[outputPositions++] = i;
            }
        }

        // Create filtered page
        Block[] blocks = new Block[page.getChannelCount()];
        for (int i = 0; i < blocks.length; i++) {
            blocks[i] = page.getBlock(i).getPositions(positions, 0, outputPositions);
        }

        return new Page(outputPositions, blocks);
    }

    private int findColumnIndex(List<HiveColumnHandle> columns, String name) {
        for (int i = 0; i < columns.size(); i++) {
            if (columns.get(i).getName().equals(name)) {
                return i;
            }
        }
        throw new IllegalArgumentException("Column not found: " + name);
    }
}
```

## Revised Task Breakdown

### Phase 3a: Engine-Agnostic Core (8-10 days)

**Task 3a.1: Define Core Interfaces** (1 day)
- `SecurityConfig` class (holds policy provider + user context)
- `SecurityPolicyProvider` interface
- `UserContext` class
- `PermittedMask` class
- `SecuredParquetReader` base class
- No dependencies on any query engine

**Task 3a.2: Implement OPA Provider** (2 days)
- `OpaSecurityPolicyProvider` implementation
- HTTP client for OPA REST API
- JSON request/response handling
- Error handling with fail-open/fail-closed
- Still engine-agnostic (just calls OPA)

**Task 3a.3: Implement Bitmap Filtering Logic** (2 days)
- Extract `_sec_lo` and `_sec_hi` from Parquet records
- Compute forbidden masks: `(~permitted) & 0x7FFF_FFFF_FFFF_FFFF`
- Apply filtering: `(sec_lo & forbidden_lo) == 0 && (sec_hi & forbidden_hi) == 0`
- Handle missing security columns gracefully

**Task 3a.4: Unit Tests for Core** (2 days)
- Test bitmap arithmetic
- Test OPA provider (mock OPA server)
- Test fail-open vs fail-closed behavior
- Test edge cases (missing columns, null values)

**Task 3a.5: Performance Benchmarks** (1 day)
- Measure overhead of security filtering
- Profile hot paths
- Optimize bitmap operations

### Phase 3b: Spark Integration (2-3 days)

**Task 3b.1: Implement Spark Configuration Reader** (1 day)
- Read `spark.security.*` configuration
- Create `SecurityConfig` object
- Pass to `SecuredParquetReader`
- No business logic, just config translation

**Task 3b.2: Override Spark's Parquet Reader** (1 day)
- Extend `ParquetFileFormat`
- Apply security filtering to `Iterator[InternalRow]`
- Find `_sec_lo` and `_sec_hi` column positions
- Register as Spark data source

**Task 3b.3: Integration Tests** (1 day)
- End-to-end tests with real Spark + OPA
- Verify APAC filtering, PHI exclusion
- Test fail-closed on OPA unreachable
- Verify same results as prototype

### Phase 3c: Trino Integration (2-3 days)

**Task 3c.1: Implement Trino Configuration Reader** (1 day)
- Read Trino session properties
- Create `SecurityConfig` object
- Pass to `SecuredParquetReader`

**Task 3c.2: Override Trino's Parquet Reader** (1 day)
- Implement `ConnectorPageSource`
- Apply security filtering to `Page`
- Register as Trino connector plugin

**Task 3c.3: Integration Tests** (1 day)
- End-to-end tests with real Trino + OPA
- Verify same behavior as Spark integration

### Phase 3d: Additional Engine Integrations (Optional)

**Task 3d.1: Flink Integration** (2-3 days)
- Read Flink configuration
- Override Flink's Parquet reader
- Wrap Flink's `RowData` iterator

**Task 3d.2: DuckDB Integration** (2-3 days)
- Read DuckDB configuration
- Override DuckDB's Parquet reader
- C++ implementation

**Task 3d.3: Presto Integration** (2-3 days)
- Similar to Trino integration

## Key Architectural Principles (Enforced)

1. **Engine-Agnostic Core**: `parquet-security-core` has ZERO dependencies on Spark, Trino, Flink, etc.

2. **Configuration-Driven**: The reader accepts a `SecurityConfig` object as a constructor parameter. It never fetches configuration itself.

3. **Pluggable Policy Providers**: OPA is just one implementation. Others can be added:
   - `HardcodedPolicyProvider` (for testing)
   - `AzureAdPolicyProvider` (calls Azure AD)
   - `CustomPolicyProvider` (user-defined logic)

4. **No Adapters Needed**: Application code (Spark/Trino/Flink) directly:
   - Reads its own configuration (from wherever it stores config)
   - Creates `SecurityConfig` object
   - Passes config to `SecuredParquetReader`

5. **Single Implementation, Multiple Engines**: One implementation of bitmap filtering logic. Each engine just passes its config to it.

## Testing Strategy

```
┌──────────────────────────────────────┐
│  Unit Tests (parquet-security-core)  │
│  - Bitmap arithmetic                  │
│  - OPA provider (mocked)             │
│  - Fail-open/fail-closed             │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│  Integration Tests (Spark adapter)   │
│  - Real Spark + Real OPA             │
│  - End-to-end filtering              │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│  Integration Tests (Trino adapter)   │
│  - Real Trino + Real OPA             │
│  - Same scenarios as Spark           │
└──────────────────────────────────────┘

┌──────────────────────────────────────┐
│  Cross-Engine Validation             │
│  - Same data + same policy           │
│  - Verify identical results          │
└──────────────────────────────────────┘
```

## Configuration Flow (Example)

```
┌─────────────────────────────────────────────────────────────┐
│  Spark Configuration (spark.conf)                          │
│  ------------------------------------------------            │
│  spark.security.opa.url = http://localhost:8181            │
│  spark.security.user.id = analyst@co.com                   │
│  spark.security.user.roles = analyst,apac_reader           │
│  spark.security.user.jurisdiction = IN                     │
│  spark.security.fail_open = false                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Spark Application Code                                     │
│  ------------------------------------------------            │
│  val opaUrl = spark.conf.get("spark.security.opa.url")    │
│  val userId = spark.conf.get("spark.security.user.id")    │
│  val roles = spark.conf.get("spark.security.user.roles")  │
│                                                             │
│  val provider = new OpaSecurityPolicyProvider(opaUrl)      │
│  val context = new UserContext(userId, roles, ...)         │
│  val config = new SecurityConfig(provider, context)        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  SecuredParquetReader (Engine-Agnostic)                    │
│  ------------------------------------------------            │
│  new SecuredParquetReader(readSupport, config)             │
│                                                             │
│  - Calls config.getPolicyProvider().getPermittedMask()     │
│  - Applies bitmap filtering                                 │
│  - Returns filtered records                                 │
└─────────────────────────────────────────────────────────────┘
```

**Same pattern for Trino, Flink, DuckDB**:
- Each engine reads its own configuration
- Translates to `SecurityConfig`
- Passes to `SecuredParquetReader`

## Migration Path

**Step 1**: Implement engine-agnostic core + OPA provider (Phase 3a)
**Step 2**: Implement Spark integration (Phase 3b)
**Step 3**: Test end-to-end with current prototype
**Step 4**: Implement Trino integration (Phase 3c)
**Step 5**: Cross-engine validation
**Step 6**: Additional engines as needed (Phase 3d)

## Timeline Estimate

- Phase 3a (Core): **8-10 days**
- Phase 3b (Spark): **2-3 days**
- Phase 3c (Trino): **2-3 days**
- **Total: 12-16 days** (for Spark + Trino integrations)

Each additional engine integration: **2-3 days**

## Success Criteria

✅ Zero Spark/Trino imports in `parquet-security-core`
✅ `SecuredParquetReader` accepts only `SecurityConfig`, never fetches config itself
✅ Same data + same policy = identical results across all engines
✅ OPA policy provider is swappable without changing any engine code
✅ New engine integrations just read config and pass to reader (no "adapters" needed)
✅ Performance overhead < 5% vs native Parquet readers
