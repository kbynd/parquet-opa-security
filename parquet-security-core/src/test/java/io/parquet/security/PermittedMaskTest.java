package io.parquet.security;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for PermittedMask bitmap filtering logic.
 */
class PermittedMaskTest {

    @Test
    void testIsPermitted_AllPermitted() {
        // User permitted for everything
        PermittedMask mask = new PermittedMask(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL);

        // Any row should be permitted
        assertTrue(mask.isPermitted(0x1, 0x0));
        assertTrue(mask.isPermitted(0xFF, 0x0));
        assertTrue(mask.isPermitted(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL));
    }

    @Test
    void testIsPermitted_NonePermitted() {
        // User permitted for nothing
        PermittedMask mask = new PermittedMask(0x0, 0x0);

        // Only rows with no bits set should be permitted
        assertTrue(mask.isPermitted(0x0, 0x0));
        assertFalse(mask.isPermitted(0x1, 0x0));
        assertFalse(mask.isPermitted(0xFF, 0x0));
    }

    @Test
    void testIsPermitted_SelectiveMask() {
        // User permitted for bits 0, 1, 8 (internal, confidential, pii)
        // Bit 0 = 0x1 (internal)
        // Bit 1 = 0x2 (confidential)
        // Bit 8 = 0x100 (pii)
        PermittedMask mask = new PermittedMask(0x103, 0x0);

        // Row with only permitted bits - allowed
        assertTrue(mask.isPermitted(0x1, 0x0));    // internal only
        assertTrue(mask.isPermitted(0x2, 0x0));    // confidential only
        assertTrue(mask.isPermitted(0x100, 0x0));  // pii only
        assertTrue(mask.isPermitted(0x103, 0x0));  // all permitted bits

        // Row with forbidden bit 3 (restricted) - denied
        assertFalse(mask.isPermitted(0x8, 0x0));   // restricted only
        assertFalse(mask.isPermitted(0xB, 0x0));   // internal + confidential + restricted
    }

    @Test
    void testIsPermitted_RegionalFiltering() {
        // User permitted for APAC region only
        // Bit 16 = 0x10000 (region_apac)
        PermittedMask mask = new PermittedMask(0x10000, 0x0);

        // APAC row - allowed
        assertTrue(mask.isPermitted(0x10000, 0x0));

        // EMEA row - denied
        // Bit 17 = 0x20000 (region_emea)
        assertFalse(mask.isPermitted(0x20000, 0x0));

        // AMER row - denied
        // Bit 18 = 0x40000 (region_amer)
        assertFalse(mask.isPermitted(0x40000, 0x0));
    }

    @Test
    void testIsPermitted_PHIProtection() {
        // User permitted for pii but NOT phi
        // Bit 8 = 0x100 (pii)
        // Bit 9 = 0x200 (phi)
        PermittedMask mask = new PermittedMask(0x100, 0x0);

        // Row with pii only - allowed
        assertTrue(mask.isPermitted(0x100, 0x0));

        // Row with phi - denied
        assertFalse(mask.isPermitted(0x200, 0x0));

        // Row with both pii and phi - denied (has forbidden phi bit)
        assertFalse(mask.isPermitted(0x300, 0x0));
    }

    @Test
    void testIsPermitted_HighBits() {
        // Test _sec_hi filtering
        PermittedMask mask = new PermittedMask(0x0, 0x1);

        // Row with permitted high bit - allowed
        assertTrue(mask.isPermitted(0x0, 0x1));

        // Row with forbidden high bit - denied
        assertFalse(mask.isPermitted(0x0, 0x2));
    }

    @Test
    void testIsPermittedWithVersion() {
        // User permitted for bits 0, 1
        PermittedMask mask = new PermittedMask(0x3, 0x0);

        // Row with version 1 in bits 60-63 and permitted characterization
        // Version 1 = 0x1000_0000_0000_0000
        // Characterization = 0x1 (internal)
        long secLoWithVersion = 0x1000_0000_0000_0001L;

        // Should extract version and check only characterization bits
        assertTrue(mask.isPermittedWithVersion(secLoWithVersion, 0x0));

        // Row with version but forbidden characterization bit
        secLoWithVersion = 0x1000_0000_0000_0004L; // bit 2 set, not permitted

        assertFalse(mask.isPermittedWithVersion(secLoWithVersion, 0x0));
    }

    @Test
    void testEquals() {
        PermittedMask mask1 = new PermittedMask(0x123, 0x456);
        PermittedMask mask2 = new PermittedMask(0x123, 0x456);
        PermittedMask mask3 = new PermittedMask(0x123, 0x789);

        assertEquals(mask1, mask2);
        assertNotEquals(mask1, mask3);
    }

    @Test
    void testToString() {
        PermittedMask mask = new PermittedMask(0x123, 0x456);
        String str = mask.toString();

        assertTrue(str.contains("0x123"));
        assertTrue(str.contains("0x456"));
    }

    @Test
    void testIsPermitted_EdgeCase_MaxValue() {
        // Test with maximum 63-bit value (bit 63 is used for sign)
        PermittedMask mask = new PermittedMask(0x7FFF_FFFF_FFFF_FFFFL, 0x7FFF_FFFF_FFFF_FFFFL);

        // All bits permitted
        assertTrue(mask.isPermitted(0x7FFF_FFFF_FFFF_FFFFL, 0x7FFF_FFFF_FFFF_FFFFL));
        assertTrue(mask.isPermitted(0x1, 0x0));
        assertTrue(mask.isPermitted(0x0, 0x1));
    }

    @Test
    void testIsPermitted_EdgeCase_SignBit() {
        // Test that sign bit (bit 63) is properly masked
        PermittedMask mask = new PermittedMask(0x8000_0000_0000_0000L, 0x0);

        // Even though bit 63 is set in permitted mask, the masking to 63 bits should handle it
        // The forbidden mask computation: (~permitted) & 0x7FFF_FFFF_FFFF_FFFF
        // should not include the sign bit
        assertTrue(mask.isPermitted(0x0, 0x0));
    }

    @Test
    void testIsPermitted_CombinedLoAndHi() {
        // User permitted for some lo bits and some hi bits
        PermittedMask mask = new PermittedMask(0xFF, 0xFF00);

        // Row with only permitted lo bits - allowed
        assertTrue(mask.isPermitted(0x1, 0x0));
        assertTrue(mask.isPermitted(0xFF, 0x0));

        // Row with only permitted hi bits - allowed
        assertTrue(mask.isPermitted(0x0, 0x100));
        assertTrue(mask.isPermitted(0x0, 0xFF00));

        // Row with both permitted lo and hi - allowed
        assertTrue(mask.isPermitted(0xFF, 0xFF00));

        // Row with forbidden lo bit - denied
        assertFalse(mask.isPermitted(0x100, 0x0));

        // Row with forbidden hi bit - denied
        assertFalse(mask.isPermitted(0x0, 0x1));

        // Row with permitted lo but forbidden hi - denied
        assertFalse(mask.isPermitted(0x1, 0x1));

        // Row with forbidden lo but permitted hi - denied
        assertFalse(mask.isPermitted(0x100, 0x100));
    }

    @Test
    void testIsPermitted_RealWorldScenario_APAC_PII() {
        // Real-world scenario: User permitted for APAC region + PII
        // Bit 8 = 0x100 (pii)
        // Bit 16 = 0x10000 (region_apac)
        PermittedMask mask = new PermittedMask(0x10100, 0x0);

        // Row with PII in APAC - allowed
        assertTrue(mask.isPermitted(0x10100, 0x0));

        // Row with PII only (no region) - allowed
        assertTrue(mask.isPermitted(0x100, 0x0));

        // Row with APAC only - allowed
        assertTrue(mask.isPermitted(0x10000, 0x0));

        // Row with PHI (bit 9 = 0x200) in APAC - denied
        assertFalse(mask.isPermitted(0x10200, 0x0));

        // Row with PII in EMEA (bit 17 = 0x20000) - denied
        assertFalse(mask.isPermitted(0x20100, 0x0));
    }

    @Test
    void testIsPermitted_EmptyRow() {
        // Row with no security dimensions
        PermittedMask mask = new PermittedMask(0x123, 0x456);

        // Empty row should always be permitted
        assertTrue(mask.isPermitted(0x0, 0x0));
    }

    @Test
    void testHashCode() {
        PermittedMask mask1 = new PermittedMask(0x123, 0x456);
        PermittedMask mask2 = new PermittedMask(0x123, 0x456);
        PermittedMask mask3 = new PermittedMask(0x123, 0x789);

        assertEquals(mask1.hashCode(), mask2.hashCode());
        assertNotEquals(mask1.hashCode(), mask3.hashCode());
    }

    @Test
    void testIsPermitted_ForbiddenMaskCalculation() {
        // Verify forbidden mask calculation correctness
        // permitted = 0x3 (bits 0 and 1)
        // forbidden = ~0x3 & 0x7FFF_FFFF_FFFF_FFFF = 0x7FFF_FFFF_FFFF_FFFC
        PermittedMask mask = new PermittedMask(0x3, 0x0);

        // Row with bit 2 set (0x4) - should be forbidden
        assertFalse(mask.isPermitted(0x4, 0x0));

        // Row with bit 0 set (0x1) - should be permitted
        assertTrue(mask.isPermitted(0x1, 0x0));

        // Row with bits 0 and 2 set (0x5) - should be forbidden (has forbidden bit 2)
        assertFalse(mask.isPermitted(0x5, 0x0));
    }

    @Test
    void testIsPermittedWithVersion_VersionExtraction() {
        // User permitted for bits 0, 1
        PermittedMask mask = new PermittedMask(0x3, 0x0);

        // Row with version 1 (bits 60-63 = 0x1) and permitted characterization
        // Version 1 = 0x1000_0000_0000_0000
        // Characterization = 0x1 (internal)
        long secLoWithVersion = 0x1000_0000_0000_0001L;

        // Should extract version and check only characterization bits
        assertTrue(mask.isPermittedWithVersion(secLoWithVersion, 0x0));

        // Row with version 2 and forbidden characterization bit
        // Version 2 = 0x2000_0000_0000_0000
        // Characterization = 0x4 (bit 2 set, not permitted)
        secLoWithVersion = 0x2000_0000_0000_0004L;

        assertFalse(mask.isPermittedWithVersion(secLoWithVersion, 0x0));
    }

    @Test
    void testIsPermittedWithVersion_VersionZero() {
        PermittedMask mask = new PermittedMask(0x1, 0x0);

        // Row with version 0 (no version bits set)
        long secLoWithVersion = 0x0000_0000_0000_0001L;

        assertTrue(mask.isPermittedWithVersion(secLoWithVersion, 0x0));
    }

    @Test
    void testIsPermittedWithVersion_MaxVersion() {
        PermittedMask mask = new PermittedMask(0x1, 0x0);

        // Row with version 15 (max 4-bit version)
        // Version 15 = 0xF000_0000_0000_0000
        long secLoWithVersion = 0xF000_0000_0000_0001L;

        assertTrue(mask.isPermittedWithVersion(secLoWithVersion, 0x0));
    }
}
