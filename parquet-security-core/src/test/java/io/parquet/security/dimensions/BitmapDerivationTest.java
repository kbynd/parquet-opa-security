package io.parquet.security.dimensions;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class BitmapDerivationTest {

    @Test
    void testDeriveRowBitmap_SensitivityOnly() {
        // Create metadata for a single column with sensitivity
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("name", createMetadata("name", "internal", null, null, null, null));

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                Collections.emptyMap()
        );

        // Should have internal bit set
        assertEquals(0x2L, bitmap.secLo & 0xFL);

        // Validate
        List<String> errors = BitmapDerivation.validate(bitmap);
        assertTrue(errors.isEmpty(), "Validation errors: " + errors);
    }

    @Test
    void testDeriveRowBitmap_MultipleColumns_MaxSensitivity() {
        // Multiple columns with different sensitivity levels
        // Should use the HIGHEST level
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("name", createMetadata("name", "public", null, null, null, null));
        metadata.put("email", createMetadata("email", "internal", null, null, null, null));
        metadata.put("salary", createMetadata("salary", "confidential", null, null, null, null));

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                Collections.emptyMap()
        );

        // Should have confidential bit set (highest level)
        long sensitivityBits = bitmap.secLo & 0xFL;
        assertEquals(0x4L, sensitivityBits); // Only confidential bit

        // Exactly one bit should be set
        assertEquals(1, Long.bitCount(sensitivityBits));
    }

    @Test
    void testDeriveRowBitmap_RegulatoryScopes() {
        // Multiple regulatory scopes should accumulate
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("email", createMetadata("email", "internal",
                Arrays.asList("pii"), null, null, null));
        metadata.put("salary", createMetadata("salary", "confidential",
                Arrays.asList("pii", "financial"), null, null, null));

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                Collections.emptyMap()
        );

        // Should have PII and Financial bits set
        long regulatory = bitmap.secLo & 0xFFFF00L;
        assertTrue((regulatory & SecurityDimensionsRegistry.getRegulatoryBit("pii")) != 0);
        assertTrue((regulatory & SecurityDimensionsRegistry.getRegulatoryBit("financial")) != 0);
    }

    @Test
    void testDeriveRowBitmap_GeographicConstant() {
        // Geographic scope from metadata (constant)
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("customer_id", createMetadata("customer_id", "internal",
                null, Arrays.asList("apac", "emea"), null, null));

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                Collections.emptyMap()
        );

        // Should have APAC and EMEA bits set
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getGeographicBit("apac")) != 0);
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getGeographicBit("emea")) != 0);
    }

    @Test
    void testDeriveRowBitmap_GeographicValueBased() {
        // Geographic scope from row value
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("region", createMetadataValueBased("region", null, null, null));

        Map<String, Object> rowValues = new HashMap<>();
        rowValues.put("region", "APAC");

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                rowValues
        );

        // Should have APAC bit set (from row value)
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getGeographicBit("apac")) != 0);
        assertFalse((bitmap.secLo & SecurityDimensionsRegistry.getGeographicBit("emea")) != 0);
    }

    @Test
    void testDeriveRowBitmap_Purpose() {
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("customer_id", createMetadata("customer_id", "internal",
                null, null, Arrays.asList("analytics", "operations"), null));

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                Collections.emptyMap()
        );

        // Should have analytics and operations bits set
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getPurposeBit("analytics")) != 0);
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getPurposeBit("operations")) != 0);
    }

    @Test
    void testDeriveRowBitmap_DataType() {
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("email", createMetadata("email", "internal",
                null, null, null, "customer_data"));

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                Collections.emptyMap()
        );

        // Should have customer_data bit set
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getDatatypeBit("customer_data")) != 0);
    }

    @Test
    void testDeriveRowBitmap_AllDimensions() {
        // Test with all dimensions combined
        Map<String, ColumnSecurityMetadata> metadata = new HashMap<>();
        metadata.put("email", createMetadata("email", "confidential",
                Arrays.asList("pii", "phi"), null,
                Arrays.asList("analytics"), "customer_data"));
        metadata.put("region", createMetadataValueBased("region", null, null, null));

        Map<String, Object> rowValues = new HashMap<>();
        rowValues.put("region", "APAC");

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveRowBitmap(
                metadata,
                rowValues
        );

        // Verify all dimensions are set
        Map<String, List<String>> decoded = SecurityDimensionsRegistry.decode(bitmap.secLo, bitmap.secHi);

        assertEquals(Arrays.asList("confidential"), decoded.get("sensitivity"));
        assertTrue(decoded.get("regulatory").containsAll(Arrays.asList("pii", "phi")));
        assertEquals(Arrays.asList("apac"), decoded.get("geographic"));
        assertEquals(Arrays.asList("analytics"), decoded.get("purpose"));
        assertEquals(Arrays.asList("customer_data"), decoded.get("datatype"));

        // Validate
        List<String> errors = BitmapDerivation.validate(bitmap);
        assertTrue(errors.isEmpty(), "Validation errors: " + errors);
    }

    @Test
    void testDeriveColumnBitmap() {
        ColumnSecurityMetadata metadata = createMetadata("email", "confidential",
                Arrays.asList("pii"), null, Arrays.asList("analytics"), "customer_data");

        BitmapDerivation.SecurityBitmap bitmap = BitmapDerivation.deriveColumnBitmap(
                metadata,
                null
        );

        // Verify dimensions
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getSensitivityBit("confidential")) != 0);
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getRegulatoryBit("pii")) != 0);
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getPurposeBit("analytics")) != 0);
        assertTrue((bitmap.secLo & SecurityDimensionsRegistry.getDatatypeBit("customer_data")) != 0);
    }

    @Test
    void testValidate_ValidBitmap() {
        BitmapDerivation.SecurityBitmap bitmap = new BitmapDerivation.SecurityBitmap(
                SecurityDimensionsRegistry.getSensitivityBit("confidential")
                        | (((long) SecurityDimensionsRegistry.SCHEMA_VERSION) << 61),
                0L
        );

        List<String> errors = BitmapDerivation.validate(bitmap);
        assertTrue(errors.isEmpty());
    }

    @Test
    void testValidate_MultipleSensitivityBits() {
        // Invalid: multiple sensitivity bits set
        long secLo = SecurityDimensionsRegistry.getSensitivityBit("public")
                | SecurityDimensionsRegistry.getSensitivityBit("confidential");

        BitmapDerivation.SecurityBitmap bitmap = new BitmapDerivation.SecurityBitmap(secLo, 0L);

        List<String> errors = BitmapDerivation.validate(bitmap);
        assertFalse(errors.isEmpty());
        assertTrue(errors.get(0).contains("Multiple sensitivity levels"));
    }

    @Test
    void testDescribe() {
        long secLo = SecurityDimensionsRegistry.getSensitivityBit("confidential")
                | SecurityDimensionsRegistry.getRegulatoryBit("pii")
                | SecurityDimensionsRegistry.getGeographicBit("apac")
                | (((long) SecurityDimensionsRegistry.SCHEMA_VERSION) << 61);

        BitmapDerivation.SecurityBitmap bitmap = new BitmapDerivation.SecurityBitmap(secLo, 0L);

        String description = BitmapDerivation.describe(bitmap);

        assertTrue(description.contains("confidential"));
        assertTrue(description.contains("pii"));
        assertTrue(description.contains("apac"));
    }

    @Test
    void testSecurityBitmap_Equality() {
        BitmapDerivation.SecurityBitmap bitmap1 = new BitmapDerivation.SecurityBitmap(123L, 456L);
        BitmapDerivation.SecurityBitmap bitmap2 = new BitmapDerivation.SecurityBitmap(123L, 456L);
        BitmapDerivation.SecurityBitmap bitmap3 = new BitmapDerivation.SecurityBitmap(789L, 456L);

        assertEquals(bitmap1, bitmap2);
        assertNotEquals(bitmap1, bitmap3);
        assertEquals(bitmap1.hashCode(), bitmap2.hashCode());
    }

    // Helper methods to create test metadata

    private ColumnSecurityMetadata createMetadata(
            String columnName,
            String sensitivity,
            List<String> regulatory,
            List<String> geographic,
            List<String> purposes,
            String datatype
    ) {
        return new ColumnSecurityMetadata(
                columnName,
                sensitivity,
                regulatory != null ? regulatory : Collections.emptyList(),
                geographic != null ? geographic : Collections.emptyList(),
                false,
                purposes != null ? purposes : Collections.emptyList(),
                datatype,
                "test"
        );
    }

    private ColumnSecurityMetadata createMetadataValueBased(
            String columnName,
            String sensitivity,
            List<String> regulatory,
            List<String> purposes
    ) {
        return new ColumnSecurityMetadata(
                columnName,
                sensitivity,
                regulatory != null ? regulatory : Collections.emptyList(),
                Collections.emptyList(),
                true, // value-based geographic
                purposes != null ? purposes : Collections.emptyList(),
                null,
                "test"
        );
    }
}
