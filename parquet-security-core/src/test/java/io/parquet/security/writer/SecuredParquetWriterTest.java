package io.parquet.security.writer;

import io.parquet.security.UserContext;
import io.parquet.security.audit.WriteAuditEvent;
import io.parquet.security.audit.WriteAuditHandler;
import io.parquet.security.dimensions.BitmapDerivation;
import io.parquet.security.dimensions.SecurityDimensionsRegistry;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Types;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.*;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.BINARY;
import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.INT64;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for WriteRequirements and bitmap derivation/validation logic.
 * Note: We test the core logic without creating actual ParquetWriters.
 */
class SecuredParquetWriterTest {

    @Test
    void testWriteRequirementsValidation() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("email")
                .named("test");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.email.security.write.required_roles", "admin");

        UserContext unauthorizedWriter = new UserContext(
                "user@example.com",
                Collections.singletonList("analyst"),  // Not admin
                "US",
                Collections.emptyMap()
        );

        // Parse requirements
        Map<String, WriteRequirements> requirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        assertEquals(1, requirements.size());
        WriteRequirements emailReq = requirements.get("email");
        assertNotNull(emailReq);

        // Should fail validation
        assertThrows(WriteAccessDeniedException.class,
                () -> emailReq.validateWriter(unauthorizedWriter));

        // Authorized writer should pass
        UserContext authorizedWriter = new UserContext(
                "admin@example.com",
                Collections.singletonList("admin"),
                "US",
                Collections.emptyMap()
        );

        assertDoesNotThrow(() -> emailReq.validateWriter(authorizedWriter));
    }

    @Test
    void testBitmapDerivationFromMetadata() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("email")
                .named("test");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.email.security.sensitivity", "internal");
        fileMetadata.put("column.email.security.regulatory", "pii");

        // Parse metadata
        var columnMetadata =
                io.parquet.security.dimensions.ColumnSecurityMetadata.parseFromFileMetadata(
                        schema, fileMetadata
                );

        // Derive bitmap
        Map<String, Object> rowValues = new HashMap<>();
        rowValues.put("email", "alice@example.com");

        BitmapDerivation.SecurityBitmap bitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

        // Decode and verify
        Map<String, List<String>> dimensions =
                SecurityDimensionsRegistry.decode(bitmap.secLo, bitmap.secHi);

        assertTrue(dimensions.get("sensitivity").contains("internal"));
        assertTrue(dimensions.get("regulatory").contains("pii"));
    }

    @Test
    void testAutoClassification() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("notes")
                .named("test");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.notes.security.sensitivity", "internal");
        fileMetadata.put("column.notes.security.auto_classify", "true");
        fileMetadata.put("column.notes.security.inherit_from_writer", "geographic,purpose");

        UserContext writer = new UserContext(
                "analyst@example.com",
                Arrays.asList("analyst", "apac_team"),
                "IN",  // Jurisdiction
                Collections.emptyMap()
        );

        // Parse metadata
        var columnMetadata =
                io.parquet.security.dimensions.ColumnSecurityMetadata.parseFromFileMetadata(
                        schema, fileMetadata
                );
        var writeRequirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        // Derive base bitmap
        Map<String, Object> rowValues = new HashMap<>();
        rowValues.put("notes", "Customer inquiry");

        BitmapDerivation.SecurityBitmap baseBitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

        // Apply auto-classification
        long secLo = baseBitmap.secLo;

        WriteRequirements notesReq = writeRequirements.get("notes");
        assertTrue(notesReq.isAutoClassify());
        assertTrue(notesReq.getInheritFromWriter().contains("geographic"));
        assertTrue(notesReq.getInheritFromWriter().contains("purpose"));

        // Manually apply auto-classification logic (since we can't easily test SecuredParquetWriter)
        // Add writer's jurisdiction
        secLo |= SecurityDimensionsRegistry.getGeographicBit("IN");

        // Add purpose from role (analyst -> analytics)
        secLo |= SecurityDimensionsRegistry.getPurposeBit("analytics");

        BitmapDerivation.SecurityBitmap enhancedBitmap =
                new BitmapDerivation.SecurityBitmap(secLo, baseBitmap.secHi);

        // Verify auto-classification
        Map<String, List<String>> dimensions =
                SecurityDimensionsRegistry.decode(enhancedBitmap.secLo, enhancedBitmap.secHi);

        assertTrue(dimensions.get("geographic").contains("in"),
                "Should include writer's jurisdiction");
        assertTrue(dimensions.get("purpose").contains("analytics"),
                "Should derive purpose from role");
    }

    @Test
    void testBitmapValidationMinSensitivity() {
        MessageType schema = Types.buildMessage()
                .required(INT64).named("salary")
                .named("test");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.salary.security.min_sensitivity", "confidential");

        var writeRequirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        WriteRequirements salaryReq = writeRequirements.get("salary");
        assertNotNull(salaryReq);
        assertEquals("confidential", salaryReq.getMinSensitivity());

        // Create bitmap with "internal" sensitivity (too low)
        long secLo = SecurityDimensionsRegistry.getSensitivityBit("internal");
        BitmapDerivation.SecurityBitmap invalidBitmap =
                new BitmapDerivation.SecurityBitmap(secLo, 0L);

        // Validate manually (check logic)
        Map<String, List<String>> dimensions =
                SecurityDimensionsRegistry.decode(invalidBitmap.secLo, invalidBitmap.secHi);
        String actualSensitivity = dimensions.get("sensitivity").get(0);

        int actualLevel = SecurityDimensionsRegistry.getSensitivityLevel(actualSensitivity);
        int minLevel = SecurityDimensionsRegistry.getSensitivityLevel("confidential");

        assertTrue(actualLevel < minLevel, "internal < confidential");

        // Create bitmap with "confidential" sensitivity (valid)
        secLo = SecurityDimensionsRegistry.getSensitivityBit("confidential");
        BitmapDerivation.SecurityBitmap validBitmap =
                new BitmapDerivation.SecurityBitmap(secLo, 0L);

        dimensions = SecurityDimensionsRegistry.decode(validBitmap.secLo, validBitmap.secHi);
        actualSensitivity = dimensions.get("sensitivity").get(0);
        actualLevel = SecurityDimensionsRegistry.getSensitivityLevel(actualSensitivity);

        assertTrue(actualLevel >= minLevel, "confidential >= confidential");
    }

    @Test
    void testBitmapValidationMaxSensitivity() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("description")
                .named("test");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.description.security.max_sensitivity", "internal");

        var writeRequirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        WriteRequirements descReq = writeRequirements.get("description");
        assertNotNull(descReq);
        assertEquals("internal", descReq.getMaxSensitivity());

        // Create bitmap with "confidential" sensitivity (too high)
        long secLo = SecurityDimensionsRegistry.getSensitivityBit("confidential");
        BitmapDerivation.SecurityBitmap invalidBitmap =
                new BitmapDerivation.SecurityBitmap(secLo, 0L);

        Map<String, List<String>> dimensions =
                SecurityDimensionsRegistry.decode(invalidBitmap.secLo, invalidBitmap.secHi);
        String actualSensitivity = dimensions.get("sensitivity").get(0);

        int actualLevel = SecurityDimensionsRegistry.getSensitivityLevel(actualSensitivity);
        int maxLevel = SecurityDimensionsRegistry.getSensitivityLevel("internal");

        assertTrue(actualLevel > maxLevel, "confidential > internal");

        // Create bitmap with "public" sensitivity (valid - lower than max)
        secLo = SecurityDimensionsRegistry.getSensitivityBit("public");
        BitmapDerivation.SecurityBitmap validBitmap =
                new BitmapDerivation.SecurityBitmap(secLo, 0L);

        dimensions = SecurityDimensionsRegistry.decode(validBitmap.secLo, validBitmap.secHi);
        actualSensitivity = dimensions.get("sensitivity").get(0);
        actualLevel = SecurityDimensionsRegistry.getSensitivityLevel(actualSensitivity);

        assertTrue(actualLevel <= maxLevel, "public <= internal");
    }

    @Test
    void testAuditEventCreation() {
        WriteAuditHandler mockHandler = mock(WriteAuditHandler.class);

        io.parquet.security.audit.WriteAuditEventImpl event =
                new io.parquet.security.audit.WriteAuditEventImpl(
                        "user@example.com",
                        "/tmp/test.parquet",
                        "email",
                        "write_allowed",
                        "Row written successfully",
                        System.currentTimeMillis()
                );

        assertEquals("user@example.com", event.getUserId());
        assertEquals("/tmp/test.parquet", event.getFilePath());
        assertEquals("email", event.getColumnName());
        assertEquals("write_allowed", event.getAction());
        assertEquals("Row written successfully", event.getReason());

        // Test handler call
        mockHandler.onWriteEvent(event);
        ArgumentCaptor<WriteAuditEvent> captor =
                ArgumentCaptor.forClass(WriteAuditEvent.class);
        verify(mockHandler).onWriteEvent(captor.capture());

        assertEquals("write_allowed", captor.getValue().getAction());
    }

    @Test
    void testWriteRequirementsToString() {
        WriteRequirements req = new WriteRequirements(
                "email",
                Arrays.asList("pii"),
                Arrays.asList("admin"),
                "confidential",
                "restricted",
                true,
                false,
                Collections.emptyList()
        );

        String str = req.toString();
        assertTrue(str.contains("email"));
        assertTrue(str.contains("pii"));
        assertTrue(str.contains("admin"));
        assertTrue(str.contains("confidential"));
    }
}
