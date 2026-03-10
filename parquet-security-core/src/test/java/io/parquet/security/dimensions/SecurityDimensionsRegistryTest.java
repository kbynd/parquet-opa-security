package io.parquet.security.dimensions;

import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class SecurityDimensionsRegistryTest {

    @Test
    void testSensitivityBits() {
        // Test individual bit positions
        assertEquals(0x1L, SecurityDimensionsRegistry.getSensitivityBit("public"));
        assertEquals(0x2L, SecurityDimensionsRegistry.getSensitivityBit("internal"));
        assertEquals(0x4L, SecurityDimensionsRegistry.getSensitivityBit("confidential"));
        assertEquals(0x8L, SecurityDimensionsRegistry.getSensitivityBit("restricted"));

        // Test case insensitivity
        assertEquals(0x4L, SecurityDimensionsRegistry.getSensitivityBit("CONFIDENTIAL"));

        // Test unknown level
        assertEquals(0L, SecurityDimensionsRegistry.getSensitivityBit("unknown"));
    }

    @Test
    void testSensitivityLevels() {
        // Test hierarchical ordering
        assertEquals(0, SecurityDimensionsRegistry.getSensitivityLevel("public"));
        assertEquals(1, SecurityDimensionsRegistry.getSensitivityLevel("internal"));
        assertEquals(2, SecurityDimensionsRegistry.getSensitivityLevel("confidential"));
        assertEquals(3, SecurityDimensionsRegistry.getSensitivityLevel("restricted"));

        // Test unknown level
        assertEquals(-1, SecurityDimensionsRegistry.getSensitivityLevel("unknown"));
    }

    @Test
    void testPermittedSensitivityBits_ReadDown() {
        // Public user can only read public
        long publicPermitted = SecurityDimensionsRegistry.getPermittedSensitivityBits("public");
        assertEquals(0x1L, publicPermitted);

        // Internal user can read public + internal
        long internalPermitted = SecurityDimensionsRegistry.getPermittedSensitivityBits("internal");
        assertEquals(0x3L, internalPermitted); // 0x1 | 0x2

        // Confidential user can read public + internal + confidential
        long confidentialPermitted = SecurityDimensionsRegistry.getPermittedSensitivityBits("confidential");
        assertEquals(0x7L, confidentialPermitted); // 0x1 | 0x2 | 0x4

        // Restricted user can read all
        long restrictedPermitted = SecurityDimensionsRegistry.getPermittedSensitivityBits("restricted");
        assertEquals(0xFL, restrictedPermitted); // 0x1 | 0x2 | 0x4 | 0x8
    }

    @Test
    void testRegulatoryBits() {
        assertEquals(0x100L, SecurityDimensionsRegistry.getRegulatoryBit("pii"));
        assertEquals(0x200L, SecurityDimensionsRegistry.getRegulatoryBit("phi"));
        assertEquals(0x400L, SecurityDimensionsRegistry.getRegulatoryBit("pci"));
        assertEquals(0x800L, SecurityDimensionsRegistry.getRegulatoryBit("financial"));

        // Test combined scopes
        List<String> scopes = Arrays.asList("pii", "financial");
        long combined = SecurityDimensionsRegistry.getRegulatoryBits(scopes);
        assertEquals(0x900L, combined); // 0x100 | 0x800
    }

    @Test
    void testGeographicBits() {
        // Regions
        assertEquals(0x1000000L, SecurityDimensionsRegistry.getGeographicBit("apac"));
        assertEquals(0x2000000L, SecurityDimensionsRegistry.getGeographicBit("emea"));
        assertEquals(0x4000000L, SecurityDimensionsRegistry.getGeographicBit("amer"));
        assertEquals(0x8000000L, SecurityDimensionsRegistry.getGeographicBit("global"));

        // Countries
        assertEquals(0x10000000L, SecurityDimensionsRegistry.getGeographicBit("us"));
        assertEquals(0x20000000L, SecurityDimensionsRegistry.getGeographicBit("eu"));

        // Test combined
        List<String> scopes = Arrays.asList("apac", "emea");
        long combined = SecurityDimensionsRegistry.getGeographicBits(scopes);
        assertEquals(0x3000000L, combined); // 0x1000000 | 0x2000000
    }

    @Test
    void testPurposeBits() {
        assertEquals(0x10000000000L, SecurityDimensionsRegistry.getPurposeBit("analytics"));
        assertEquals(0x20000000000L, SecurityDimensionsRegistry.getPurposeBit("operations"));
        assertEquals(0x40000000000L, SecurityDimensionsRegistry.getPurposeBit("marketing"));

        // Test combined
        List<String> purposes = Arrays.asList("analytics", "operations");
        long combined = SecurityDimensionsRegistry.getPurposeBits(purposes);
        assertEquals(0x30000000000L, combined);
    }

    @Test
    void testDatatypeBits() {
        assertEquals(0x100000000000000L, SecurityDimensionsRegistry.getDatatypeBit("customer_data"));
        assertEquals(0x200000000000000L, SecurityDimensionsRegistry.getDatatypeBit("employee_data"));
        assertEquals(0x400000000000000L, SecurityDimensionsRegistry.getDatatypeBit("financial_data"));
    }

    @Test
    void testDecode() {
        // Build a bitmap with multiple dimensions
        long secLo = 0L;
        secLo |= SecurityDimensionsRegistry.getSensitivityBit("confidential");
        secLo |= SecurityDimensionsRegistry.getRegulatoryBit("pii");
        secLo |= SecurityDimensionsRegistry.getRegulatoryBit("financial");
        secLo |= SecurityDimensionsRegistry.getGeographicBit("apac");
        secLo |= SecurityDimensionsRegistry.getPurposeBit("analytics");
        secLo |= SecurityDimensionsRegistry.getDatatypeBit("customer_data");

        Map<String, List<String>> decoded = SecurityDimensionsRegistry.decode(secLo, 0L);

        assertEquals(Arrays.asList("confidential"), decoded.get("sensitivity"));
        assertTrue(decoded.get("regulatory").containsAll(Arrays.asList("pii", "financial")));
        assertEquals(Arrays.asList("apac"), decoded.get("geographic"));
        assertEquals(Arrays.asList("analytics"), decoded.get("purpose"));
        assertEquals(Arrays.asList("customer_data"), decoded.get("datatype"));
    }

    @Test
    void testBitPositionsDoNotOverlap() {
        // Verify that different dimensions don't share bits
        long sensitivity = SecurityDimensionsRegistry.getSensitivityBit("confidential");
        long regulatory = SecurityDimensionsRegistry.getRegulatoryBit("pii");
        long geographic = SecurityDimensionsRegistry.getGeographicBit("apac");
        long purpose = SecurityDimensionsRegistry.getPurposeBit("analytics");
        long datatype = SecurityDimensionsRegistry.getDatatypeBit("customer_data");

        // No overlaps
        assertEquals(0L, sensitivity & regulatory);
        assertEquals(0L, sensitivity & geographic);
        assertEquals(0L, sensitivity & purpose);
        assertEquals(0L, sensitivity & datatype);
        assertEquals(0L, regulatory & geographic);
        assertEquals(0L, regulatory & purpose);
        assertEquals(0L, regulatory & datatype);
        assertEquals(0L, geographic & purpose);
        assertEquals(0L, geographic & datatype);
        assertEquals(0L, purpose & datatype);
    }

    @Test
    void testGetAllDimensions() {
        // Verify we have expected dimension values
        assertTrue(SecurityDimensionsRegistry.getAllSensitivityLevels().contains("public"));
        assertTrue(SecurityDimensionsRegistry.getAllSensitivityLevels().contains("confidential"));

        assertTrue(SecurityDimensionsRegistry.getAllRegulatoryScopes().contains("pii"));
        assertTrue(SecurityDimensionsRegistry.getAllRegulatoryScopes().contains("phi"));

        assertTrue(SecurityDimensionsRegistry.getAllGeographicScopes().contains("apac"));
        assertTrue(SecurityDimensionsRegistry.getAllGeographicScopes().contains("us"));

        assertTrue(SecurityDimensionsRegistry.getAllPurposes().contains("analytics"));
        assertTrue(SecurityDimensionsRegistry.getAllPurposes().contains("operations"));

        assertTrue(SecurityDimensionsRegistry.getAllDatatypes().contains("customer_data"));
        assertTrue(SecurityDimensionsRegistry.getAllDatatypes().contains("employee_data"));
    }
}
