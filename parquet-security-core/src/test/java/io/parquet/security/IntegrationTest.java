package io.parquet.security;

import io.parquet.security.opa.OpaSecurityPolicyProvider;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroup;
import org.apache.parquet.hadoop.ParquetReader;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.example.GroupReadSupport;
import org.apache.parquet.hadoop.example.GroupWriteSupport;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.PrimitiveType;
import org.apache.parquet.schema.Type;
import org.apache.parquet.schema.Types;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests that require real OPA server.
 *
 * These tests are only run when OPA_URL environment variable is set:
 *   export OPA_URL=http://localhost:8181
 *   mvn test
 *
 * Start OPA with:
 *   docker-compose up -d
 */
@EnabledIfEnvironmentVariable(named = "OPA_URL", matches = ".*")
class IntegrationTest {

    private String opaUrl;

    @TempDir
    java.nio.file.Path tempDir;

    @BeforeEach
    void setUp() {
        opaUrl = System.getenv("OPA_URL");
        if (opaUrl == null) {
            opaUrl = "http://localhost:8181";
        }
    }

    /**
     * Test schema: name, age, email, _sec_lo, _sec_hi
     */
    private MessageType createTestSchema() {
        return new MessageType("test",
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.BINARY, "name"),
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.INT32, "age"),
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.BINARY, "email"),
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.INT64, "_sec_lo"),
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.INT64, "_sec_hi")
        );
    }

    /**
     * Create a test Parquet file with security columns.
     */
    private Path createSecuredParquetFile(String filename) throws IOException {
        MessageType schema = createTestSchema();
        Path filePath = new Path(tempDir.resolve(filename).toString());

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = new ParquetWriter<>(
            filePath,
            new GroupWriteSupport(),
            ParquetWriter.DEFAULT_COMPRESSION_CODEC_NAME,
            ParquetWriter.DEFAULT_BLOCK_SIZE,
            ParquetWriter.DEFAULT_PAGE_SIZE,
            ParquetWriter.DEFAULT_PAGE_SIZE,
            ParquetWriter.DEFAULT_IS_DICTIONARY_ENABLED,
            ParquetWriter.DEFAULT_IS_VALIDATING_ENABLED,
            ParquetWriter.DEFAULT_WRITER_VERSION,
            conf
        )) {
            // Record 1: Internal data, APAC region
            // Bit 0 = 0x1 (internal)
            // Bit 16 = 0x10000 (region_apac)
            Group record1 = new SimpleGroup(schema);
            record1.append("name", "Alice");
            record1.append("age", 30);
            record1.append("email", "alice@example.com");
            record1.append("_sec_lo", 0x10001L);
            record1.append("_sec_hi", 0L);
            writer.write(record1);

            // Record 2: Confidential data, PII, APAC region
            // Bit 1 = 0x2 (confidential)
            // Bit 8 = 0x100 (pii)
            // Bit 16 = 0x10000 (region_apac)
            Group record2 = new SimpleGroup(schema);
            record2.append("name", "Bob");
            record2.append("age", 35);
            record2.append("email", "bob@example.com");
            record2.append("_sec_lo", 0x10102L);
            record2.append("_sec_hi", 0L);
            writer.write(record2);

            // Record 3: Restricted data, PHI, EMEA region
            // Bit 3 = 0x8 (restricted)
            // Bit 9 = 0x200 (phi)
            // Bit 17 = 0x20000 (region_emea)
            Group record3 = new SimpleGroup(schema);
            record3.append("name", "Charlie");
            record3.append("age", 40);
            record3.append("email", "charlie@example.com");
            record3.append("_sec_lo", 0x20208L);
            record3.append("_sec_hi", 0L);
            writer.write(record3);

            // Record 4: Internal data, EMEA region
            // Bit 0 = 0x1 (internal)
            // Bit 17 = 0x20000 (region_emea)
            Group record4 = new SimpleGroup(schema);
            record4.append("name", "Dave");
            record4.append("age", 28);
            record4.append("email", "dave@example.com");
            record4.append("_sec_lo", 0x20001L);
            record4.append("_sec_hi", 0L);
            writer.write(record4);
        }

        return filePath;
    }

    @Test
    void testEndToEnd_APACAnalyst_SeesOnlyAPACRecords() throws IOException {
        // Create test file
        Path parquetFile = createSecuredParquetFile("apac_test.parquet");

        // Create OPA policy provider and get permitted mask
        OpaSecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(opaUrl, false);

        // APAC analyst user context
        UserContext user = new UserContext(
            "analyst@co.com",
            Arrays.asList("analyst", "apac_reader"),
            "IN",
            null
        );

        // Call OPA once to get permitted mask
        PermittedMask permittedMask = policyProvider.getPermittedMask(user);

        // Read file with security filtering
        Configuration conf = new Configuration();
        ParquetReader<Group> baseReader = ParquetReader.builder(new GroupReadSupport(), parquetFile)
            .withConf(conf)
            .build();

        SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
            baseReader,
            permittedMask,
            new GroupSecurityColumnExtractor()
        );

        // Should see only APAC records (Alice and Bob)
        Group record1 = reader.read();
        assertNotNull(record1);
        assertEquals("Alice", record1.getString("name", 0));

        Group record2 = reader.read();
        assertNotNull(record2);
        assertEquals("Bob", record2.getString("name", 0));

        // No more records (Charlie and Dave filtered out)
        assertNull(reader.read());

        SecuredParquetReader.FilteringStats stats = reader.getStats();
        assertEquals(4, stats.totalRecords);
        assertEquals(2, stats.filteredRecords); // Charlie and Dave filtered
        assertEquals(2, stats.passedRecords);   // Alice and Bob passed

        reader.close();
    }

    @Test
    void testEndToEnd_AdminUser_SeesAllRecords() throws IOException {
        // Create test file
        Path parquetFile = createSecuredParquetFile("admin_test.parquet");

        // Create OPA policy provider and get permitted mask
        OpaSecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(opaUrl, false);

        // Admin user context
        UserContext user = new UserContext(
            "admin@co.com",
            Collections.singletonList("admin"),
            null,
            null
        );

        // Call OPA once to get permitted mask
        PermittedMask permittedMask = policyProvider.getPermittedMask(user);

        // Read file with security filtering
        Configuration conf = new Configuration();
        ParquetReader<Group> baseReader = ParquetReader.builder(new GroupReadSupport(), parquetFile)
            .withConf(conf)
            .build();

        SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
            baseReader,
            permittedMask,
            new GroupSecurityColumnExtractor()
        );

        // Admin should see all 4 records
        assertNotNull(reader.read());
        assertNotNull(reader.read());
        assertNotNull(reader.read());
        assertNotNull(reader.read());
        assertNull(reader.read());

        SecuredParquetReader.FilteringStats stats = reader.getStats();
        assertEquals(4, stats.totalRecords);
        assertEquals(0, stats.filteredRecords);
        assertEquals(4, stats.passedRecords);

        reader.close();
    }

    @Test
    void testEndToEnd_GuestUser_SeesNothing() throws IOException {
        // Create test file
        Path parquetFile = createSecuredParquetFile("guest_test.parquet");

        // Create OPA policy provider and get permitted mask
        OpaSecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(opaUrl, false);

        // Guest user context (no roles)
        UserContext user = new UserContext(
            "guest@co.com",
            Collections.emptyList(),
            null,
            null
        );

        // Call OPA once to get permitted mask
        PermittedMask permittedMask = policyProvider.getPermittedMask(user);

        // Read file with security filtering
        Configuration conf = new Configuration();
        ParquetReader<Group> baseReader = ParquetReader.builder(new GroupReadSupport(), parquetFile)
            .withConf(conf)
            .build();

        SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
            baseReader,
            permittedMask,
            new GroupSecurityColumnExtractor()
        );

        // Guest should see no records
        assertNull(reader.read());

        SecuredParquetReader.FilteringStats stats = reader.getStats();
        assertEquals(4, stats.totalRecords);
        assertEquals(4, stats.filteredRecords);
        assertEquals(0, stats.passedRecords);

        reader.close();
    }

    @Test
    void testEndToEnd_UnsecuredFile_AllowsAllRecords() throws IOException {
        // Create unsecured file (no _sec_lo column)
        MessageType schema = new MessageType("test",
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.BINARY, "name"),
            new PrimitiveType(Type.Repetition.REQUIRED, PrimitiveType.PrimitiveTypeName.INT32, "age")
        );

        Path filePath = new Path(tempDir.resolve("unsecured.parquet").toString());

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = new ParquetWriter<>(
            filePath,
            new GroupWriteSupport(),
            ParquetWriter.DEFAULT_COMPRESSION_CODEC_NAME,
            ParquetWriter.DEFAULT_BLOCK_SIZE,
            ParquetWriter.DEFAULT_PAGE_SIZE,
            ParquetWriter.DEFAULT_PAGE_SIZE,
            ParquetWriter.DEFAULT_IS_DICTIONARY_ENABLED,
            ParquetWriter.DEFAULT_IS_VALIDATING_ENABLED,
            ParquetWriter.DEFAULT_WRITER_VERSION,
            conf
        )) {
            Group record = new SimpleGroup(schema);
            record.append("name", "Alice");
            record.append("age", 30);
            writer.write(record);
        }

        // Create OPA policy provider and get permitted mask
        OpaSecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(opaUrl, false);

        // Guest user (should see nothing in secured files)
        UserContext user = new UserContext(
            "guest@co.com",
            Collections.emptyList(),
            null,
            null
        );

        // Call OPA once to get permitted mask
        PermittedMask permittedMask = policyProvider.getPermittedMask(user);

        // Read unsecured file
        ParquetReader<Group> baseReader = ParquetReader.builder(new GroupReadSupport(), filePath)
            .withConf(conf)
            .build();

        SecuredParquetReader<Group> reader = new SecuredParquetReader<>(
            baseReader,
            permittedMask,
            new GroupSecurityColumnExtractor()
        );

        // Should see the record (unsecured file bypasses security)
        Group record = reader.read();
        assertNotNull(record);
        assertEquals("Alice", record.getString("name", 0));

        assertNull(reader.read());

        reader.close();
    }

    @Test
    void testEndToEnd_OPAUnreachable_FailClosed() {
        // Use invalid OPA URL
        OpaSecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(
            "http://localhost:9999",
            false
        );

        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should fail during policy evaluation
        assertThrows(Exception.class, () -> {
            policyProvider.getPermittedMask(user);
        });
    }

    @Test
    void testEndToEnd_OPAUnreachable_FailOpen() throws Exception {
        // Use invalid OPA URL with fail_open=true
        OpaSecurityPolicyProvider policyProvider = new OpaSecurityPolicyProvider(
            "http://localhost:9999",
            true
        );

        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should return all-permitted mask
        PermittedMask mask = policyProvider.getPermittedMask(user);

        assertEquals(0xFFFF_FFFF_FFFF_FFFFL, mask.permittedLo);
        assertEquals(0xFFFF_FFFF_FFFF_FFFFL, mask.permittedHi);
    }
}
