package io.parquet.security.dimensions;

import java.util.*;

/**
 * Derives security bitmaps from column metadata and row values.
 *
 * This is the core logic used by the characterization pipeline to stamp
 * security metadata onto Parquet rows.
 *
 * Workflow:
 * 1. Read column metadata from Parquet schema
 * 2. For each row, examine columns with security metadata
 * 3. Derive bitmap based on:
 *    - Constant metadata (sensitivity, regulatory, purpose, datatype)
 *    - Row values (for geographic scope with value_based marker)
 * 4. Combine all bitmaps into _sec_lo and _sec_hi
 *
 * Example:
 * Column "email" has metadata: {sensitivity: "internal", regulatory: "pii,gdpr"}
 * Column "region" has metadata: {geographic: "value_based"}
 * Row has: {email: "alice@example.com", region: "APAC"}
 *
 * Derived bitmap:
 * - Bit 1 (internal) from email column metadata
 * - Bit 8 (pii) from email column metadata
 * - Bit 12 (gdpr) from email column metadata
 * - Bit 24 (region_apac) from region column VALUE
 */
public class BitmapDerivation {

    /**
     * Derive security bitmap for a row based on column metadata.
     *
     * @param columnMetadata Map of column name to security metadata
     * @param rowValues Map of column name to row value (only needed for value-based columns)
     * @return SecurityBitmap with _sec_lo and _sec_hi values
     */
    public static SecurityBitmap deriveRowBitmap(
            Map<String, ColumnSecurityMetadata> columnMetadata,
            Map<String, Object> rowValues
    ) {
        long secLo = 0L;
        long secHi = 0L;

        // Track the highest sensitivity level encountered
        int maxSensitivityLevel = -1;
        String maxSensitivityName = null;

        for (Map.Entry<String, ColumnSecurityMetadata> entry : columnMetadata.entrySet()) {
            String columnName = entry.getKey();
            ColumnSecurityMetadata metadata = entry.getValue();

            // Dimension 1: Sensitivity (hierarchical - use highest level)
            if (metadata.getSensitivity() != null) {
                int level = SecurityDimensionsRegistry.getSensitivityLevel(metadata.getSensitivity());
                if (level > maxSensitivityLevel) {
                    maxSensitivityLevel = level;
                    maxSensitivityName = metadata.getSensitivity();
                }
            }

            // Dimension 2: Regulatory (compartments - accumulate all)
            for (String scope : metadata.getRegulatoryScopes()) {
                secLo |= SecurityDimensionsRegistry.getRegulatoryBit(scope);
            }

            // Dimension 3: Geographic (compartments)
            if (metadata.isGeographicValueBased()) {
                // Read value from row
                Object value = rowValues.get(columnName);
                if (value != null) {
                    String geographicValue = value.toString().trim();
                    secLo |= SecurityDimensionsRegistry.getGeographicBit(geographicValue);
                }
            } else {
                // Use constant metadata
                for (String scope : metadata.getGeographicScopes()) {
                    secLo |= SecurityDimensionsRegistry.getGeographicBit(scope);
                }
            }

            // Dimension 4: Purpose (compartments - accumulate all)
            for (String purpose : metadata.getPurposes()) {
                secLo |= SecurityDimensionsRegistry.getPurposeBit(purpose);
            }

            // Dimension 5: Data type (informational - accumulate all)
            if (metadata.getDatatype() != null) {
                secLo |= SecurityDimensionsRegistry.getDatatypeBit(metadata.getDatatype());
            }
        }

        // Set the highest sensitivity level bit (only one bit should be set)
        if (maxSensitivityName != null) {
            secLo |= SecurityDimensionsRegistry.getSensitivityBit(maxSensitivityName);
        }

        // Add schema version (bits 61-63)
        long schemaVersion = SecurityDimensionsRegistry.SCHEMA_VERSION;
        secLo |= (schemaVersion << 61);

        return new SecurityBitmap(secLo, secHi);
    }

    /**
     * Derive security bitmap for a specific column's metadata only.
     * This is useful for understanding what each column contributes.
     *
     * @param metadata Column security metadata
     * @param rowValue Optional row value (for geographic value-based)
     * @return SecurityBitmap
     */
    public static SecurityBitmap deriveColumnBitmap(
            ColumnSecurityMetadata metadata,
            Object rowValue
    ) {
        long secLo = 0L;
        long secHi = 0L;

        // Sensitivity
        if (metadata.getSensitivity() != null) {
            secLo |= SecurityDimensionsRegistry.getSensitivityBit(metadata.getSensitivity());
        }

        // Regulatory
        secLo |= SecurityDimensionsRegistry.getRegulatoryBits(metadata.getRegulatoryScopes());

        // Geographic
        if (metadata.isGeographicValueBased() && rowValue != null) {
            String geoValue = rowValue.toString().trim();
            secLo |= SecurityDimensionsRegistry.getGeographicBit(geoValue);
        } else {
            secLo |= SecurityDimensionsRegistry.getGeographicBits(metadata.getGeographicScopes());
        }

        // Purpose
        secLo |= SecurityDimensionsRegistry.getPurposeBits(metadata.getPurposes());

        // Data type
        if (metadata.getDatatype() != null) {
            secLo |= SecurityDimensionsRegistry.getDatatypeBit(metadata.getDatatype());
        }

        return new SecurityBitmap(secLo, secHi);
    }

    /**
     * Validate that a security bitmap is correctly formed.
     *
     * @param bitmap Security bitmap to validate
     * @return List of validation errors (empty if valid)
     */
    public static List<String> validate(SecurityBitmap bitmap) {
        List<String> errors = new ArrayList<>();

        // Check that only one sensitivity bit is set
        long sensitivityMask = 0xFL; // Bits 0-3
        long sensitivityBits = bitmap.secLo & sensitivityMask;
        if (Long.bitCount(sensitivityBits) > 1) {
            errors.add("Multiple sensitivity levels set: " + Long.toBinaryString(sensitivityBits));
        }

        // Check that reserved bits are not set (bits 4-7, bits beyond 63)
        long reservedLowMask = 0xF0L; // Bits 4-7
        if ((bitmap.secLo & reservedLowMask) != 0) {
            errors.add("Reserved bits 4-7 are set");
        }

        // Check schema version
        long schemaVersion = (bitmap.secLo >>> 61) & 0x7L;
        if (schemaVersion != SecurityDimensionsRegistry.SCHEMA_VERSION) {
            errors.add("Schema version mismatch: expected "
                    + SecurityDimensionsRegistry.SCHEMA_VERSION
                    + ", got " + schemaVersion);
        }

        return errors;
    }

    /**
     * Decode a bitmap into human-readable format.
     *
     * @param bitmap Security bitmap
     * @return Human-readable description
     */
    public static String describe(SecurityBitmap bitmap) {
        Map<String, List<String>> dimensions = SecurityDimensionsRegistry.decode(
                bitmap.secLo,
                bitmap.secHi
        );

        StringBuilder sb = new StringBuilder();
        sb.append("SecurityBitmap{\n");
        sb.append("  _sec_lo: 0x").append(Long.toHexString(bitmap.secLo)).append("\n");
        sb.append("  _sec_hi: 0x").append(Long.toHexString(bitmap.secHi)).append("\n");

        if (!dimensions.get("sensitivity").isEmpty()) {
            sb.append("  Sensitivity: ").append(dimensions.get("sensitivity")).append("\n");
        }
        if (!dimensions.get("regulatory").isEmpty()) {
            sb.append("  Regulatory: ").append(dimensions.get("regulatory")).append("\n");
        }
        if (!dimensions.get("geographic").isEmpty()) {
            sb.append("  Geographic: ").append(dimensions.get("geographic")).append("\n");
        }
        if (!dimensions.get("purpose").isEmpty()) {
            sb.append("  Purpose: ").append(dimensions.get("purpose")).append("\n");
        }
        if (!dimensions.get("datatype").isEmpty()) {
            sb.append("  DataType: ").append(dimensions.get("datatype")).append("\n");
        }

        sb.append("}");
        return sb.toString();
    }

    /**
     * Container for security bitmap values.
     */
    public static class SecurityBitmap {
        public final long secLo;
        public final long secHi;

        public SecurityBitmap(long secLo, long secHi) {
            this.secLo = secLo;
            this.secHi = secHi;
        }

        @Override
        public String toString() {
            return BitmapDerivation.describe(this);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            SecurityBitmap that = (SecurityBitmap) o;
            return secLo == that.secLo && secHi == that.secHi;
        }

        @Override
        public int hashCode() {
            return Objects.hash(secLo, secHi);
        }
    }
}
