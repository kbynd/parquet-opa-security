package io.parquet.security.dimensions;

import java.util.*;

/**
 * Central registry for security dimension definitions and bit allocations.
 *
 * Based on Bell-LaPadula security model with hierarchical levels and compartments.
 * This is the single source of truth for all bit assignments across the 128-bit space.
 *
 * Bit Space Allocation:
 * - _sec_lo bits 0-3: Sensitivity Level (hierarchical)
 * - _sec_lo bits 8-23: Regulatory Scope (compartments)
 * - _sec_lo bits 24-39: Geographic Scope (compartments)
 * - _sec_lo bits 40-55: Functional Purpose (compartments)
 * - _sec_lo bits 56-63: Data Type + Schema Version
 * - _sec_hi: Reserved for future use
 */
public class SecurityDimensionsRegistry {

    // Schema version (bits 61-63 of _sec_lo)
    public static final int SCHEMA_VERSION = 1;

    // ========== DIMENSION 1: SENSITIVITY LEVEL (Hierarchical) ==========
    // Bits 0-3 (4 bits, only one should be set per row)

    public static final long BIT_SENSITIVITY_PUBLIC = 0x1L;           // Bit 0
    public static final long BIT_SENSITIVITY_INTERNAL = 0x2L;         // Bit 1
    public static final long BIT_SENSITIVITY_CONFIDENTIAL = 0x4L;     // Bit 2
    public static final long BIT_SENSITIVITY_RESTRICTED = 0x8L;       // Bit 3

    private static final Map<String, Long> SENSITIVITY_BITS = new HashMap<>();
    private static final Map<String, Integer> SENSITIVITY_LEVELS = new HashMap<>();

    static {
        SENSITIVITY_BITS.put("public", BIT_SENSITIVITY_PUBLIC);
        SENSITIVITY_BITS.put("internal", BIT_SENSITIVITY_INTERNAL);
        SENSITIVITY_BITS.put("confidential", BIT_SENSITIVITY_CONFIDENTIAL);
        SENSITIVITY_BITS.put("restricted", BIT_SENSITIVITY_RESTRICTED);

        // Hierarchical ordering (higher number = more sensitive)
        SENSITIVITY_LEVELS.put("public", 0);
        SENSITIVITY_LEVELS.put("internal", 1);
        SENSITIVITY_LEVELS.put("confidential", 2);
        SENSITIVITY_LEVELS.put("restricted", 3);
    }

    // ========== DIMENSION 2: REGULATORY SCOPE (Compartments) ==========
    // Bits 8-23 (16 bits)

    public static final long BIT_REGULATORY_PII = 0x100L;             // Bit 8
    public static final long BIT_REGULATORY_PHI = 0x200L;             // Bit 9
    public static final long BIT_REGULATORY_PCI = 0x400L;             // Bit 10
    public static final long BIT_REGULATORY_FINANCIAL = 0x800L;       // Bit 11
    public static final long BIT_REGULATORY_GDPR = 0x1000L;           // Bit 12
    public static final long BIT_REGULATORY_EXPORT_CONTROL = 0x2000L; // Bit 13
    public static final long BIT_REGULATORY_LEGAL_PRIVILEGE = 0x4000L;// Bit 14
    public static final long BIT_REGULATORY_TRADE_SECRET = 0x8000L;   // Bit 15
    // Bits 16-23 reserved for future regulatory scopes

    private static final Map<String, Long> REGULATORY_BITS = new HashMap<>();

    static {
        REGULATORY_BITS.put("pii", BIT_REGULATORY_PII);
        REGULATORY_BITS.put("phi", BIT_REGULATORY_PHI);
        REGULATORY_BITS.put("pci", BIT_REGULATORY_PCI);
        REGULATORY_BITS.put("financial", BIT_REGULATORY_FINANCIAL);
        REGULATORY_BITS.put("gdpr", BIT_REGULATORY_GDPR);
        REGULATORY_BITS.put("export_control", BIT_REGULATORY_EXPORT_CONTROL);
        REGULATORY_BITS.put("legal_privilege", BIT_REGULATORY_LEGAL_PRIVILEGE);
        REGULATORY_BITS.put("trade_secret", BIT_REGULATORY_TRADE_SECRET);
    }

    // ========== DIMENSION 3: GEOGRAPHIC SCOPE (Compartments) ==========
    // Bits 24-39 (16 bits)

    // Regions (bits 24-27)
    public static final long BIT_GEO_REGION_APAC = 0x1000000L;        // Bit 24
    public static final long BIT_GEO_REGION_EMEA = 0x2000000L;        // Bit 25
    public static final long BIT_GEO_REGION_AMER = 0x4000000L;        // Bit 26
    public static final long BIT_GEO_REGION_GLOBAL = 0x8000000L;      // Bit 27

    // Countries (bits 28-35)
    public static final long BIT_GEO_COUNTRY_US = 0x10000000L;        // Bit 28
    public static final long BIT_GEO_COUNTRY_EU = 0x20000000L;        // Bit 29
    public static final long BIT_GEO_COUNTRY_CN = 0x40000000L;        // Bit 30
    public static final long BIT_GEO_COUNTRY_IN = 0x80000000L;        // Bit 31
    public static final long BIT_GEO_COUNTRY_UK = 0x100000000L;       // Bit 32
    public static final long BIT_GEO_COUNTRY_CA = 0x200000000L;       // Bit 33
    // Bits 34-39 reserved for more countries

    private static final Map<String, Long> GEOGRAPHIC_BITS = new HashMap<>();

    static {
        // Regions
        GEOGRAPHIC_BITS.put("apac", BIT_GEO_REGION_APAC);
        GEOGRAPHIC_BITS.put("emea", BIT_GEO_REGION_EMEA);
        GEOGRAPHIC_BITS.put("amer", BIT_GEO_REGION_AMER);
        GEOGRAPHIC_BITS.put("global", BIT_GEO_REGION_GLOBAL);

        // Countries
        GEOGRAPHIC_BITS.put("us", BIT_GEO_COUNTRY_US);
        GEOGRAPHIC_BITS.put("eu", BIT_GEO_COUNTRY_EU);
        GEOGRAPHIC_BITS.put("cn", BIT_GEO_COUNTRY_CN);
        GEOGRAPHIC_BITS.put("in", BIT_GEO_COUNTRY_IN);
        GEOGRAPHIC_BITS.put("uk", BIT_GEO_COUNTRY_UK);
        GEOGRAPHIC_BITS.put("ca", BIT_GEO_COUNTRY_CA);
    }

    // ========== DIMENSION 4: FUNCTIONAL PURPOSE (Compartments) ==========
    // Bits 40-55 (16 bits)

    public static final long BIT_PURPOSE_ANALYTICS = 0x10000000000L;     // Bit 40
    public static final long BIT_PURPOSE_OPERATIONS = 0x20000000000L;    // Bit 41
    public static final long BIT_PURPOSE_MARKETING = 0x40000000000L;     // Bit 42
    public static final long BIT_PURPOSE_RESEARCH = 0x80000000000L;      // Bit 43
    public static final long BIT_PURPOSE_TRAINING = 0x100000000000L;     // Bit 44
    public static final long BIT_PURPOSE_AUDIT = 0x200000000000L;        // Bit 45
    public static final long BIT_PURPOSE_SUPPORT = 0x400000000000L;      // Bit 46
    public static final long BIT_PURPOSE_DEVELOPMENT = 0x800000000000L;  // Bit 47
    // Bits 48-55 reserved for more purposes

    private static final Map<String, Long> PURPOSE_BITS = new HashMap<>();

    static {
        PURPOSE_BITS.put("analytics", BIT_PURPOSE_ANALYTICS);
        PURPOSE_BITS.put("operations", BIT_PURPOSE_OPERATIONS);
        PURPOSE_BITS.put("marketing", BIT_PURPOSE_MARKETING);
        PURPOSE_BITS.put("research", BIT_PURPOSE_RESEARCH);
        PURPOSE_BITS.put("training", BIT_PURPOSE_TRAINING);
        PURPOSE_BITS.put("audit", BIT_PURPOSE_AUDIT);
        PURPOSE_BITS.put("support", BIT_PURPOSE_SUPPORT);
        PURPOSE_BITS.put("development", BIT_PURPOSE_DEVELOPMENT);
    }

    // ========== DIMENSION 5: DATA TYPE (Informational) ==========
    // Bits 56-60 (5 bits)

    public static final long BIT_DATATYPE_CUSTOMER = 0x100000000000000L;     // Bit 56
    public static final long BIT_DATATYPE_EMPLOYEE = 0x200000000000000L;     // Bit 57
    public static final long BIT_DATATYPE_FINANCIAL = 0x400000000000000L;    // Bit 58
    public static final long BIT_DATATYPE_HEALTH = 0x800000000000000L;       // Bit 59
    public static final long BIT_DATATYPE_SYSTEM_LOGS = 0x1000000000000000L; // Bit 60
    // Bits 61-63 reserved for schema version

    private static final Map<String, Long> DATATYPE_BITS = new HashMap<>();

    static {
        DATATYPE_BITS.put("customer_data", BIT_DATATYPE_CUSTOMER);
        DATATYPE_BITS.put("employee_data", BIT_DATATYPE_EMPLOYEE);
        DATATYPE_BITS.put("financial_data", BIT_DATATYPE_FINANCIAL);
        DATATYPE_BITS.put("health_data", BIT_DATATYPE_HEALTH);
        DATATYPE_BITS.put("system_logs", BIT_DATATYPE_SYSTEM_LOGS);
    }

    // ========== PUBLIC API ==========

    /**
     * Get the bit mask for a sensitivity level.
     *
     * @param level Sensitivity level (public, internal, confidential, restricted)
     * @return Bit mask, or 0 if unknown
     */
    public static long getSensitivityBit(String level) {
        return SENSITIVITY_BITS.getOrDefault(level.toLowerCase(), 0L);
    }

    /**
     * Get the hierarchical level number for a sensitivity level.
     * Higher number = more sensitive.
     *
     * @param level Sensitivity level
     * @return Level number (0-3), or -1 if unknown
     */
    public static int getSensitivityLevel(String level) {
        return SENSITIVITY_LEVELS.getOrDefault(level.toLowerCase(), -1);
    }

    /**
     * Get all sensitivity bits that a user with given clearance can access.
     * In Bell-LaPadula, users can "read down" (access their level and below).
     *
     * @param userLevel User's clearance level
     * @return Bitmap of all permitted sensitivity levels
     */
    public static long getPermittedSensitivityBits(String userLevel) {
        int level = getSensitivityLevel(userLevel);
        if (level < 0) {
            return 0L;
        }

        long permitted = 0L;
        for (Map.Entry<String, Integer> entry : SENSITIVITY_LEVELS.entrySet()) {
            if (entry.getValue() <= level) {
                permitted |= SENSITIVITY_BITS.get(entry.getKey());
            }
        }
        return permitted;
    }

    /**
     * Get the bit mask for a regulatory scope.
     *
     * @param scope Regulatory scope (pii, phi, pci, financial, gdpr, etc.)
     * @return Bit mask, or 0 if unknown
     */
    public static long getRegulatoryBit(String scope) {
        return REGULATORY_BITS.getOrDefault(scope.toLowerCase(), 0L);
    }

    /**
     * Get combined bit mask for multiple regulatory scopes.
     *
     * @param scopes List of regulatory scopes
     * @return Combined bitmap
     */
    public static long getRegulatoryBits(Collection<String> scopes) {
        long bitmap = 0L;
        for (String scope : scopes) {
            bitmap |= getRegulatoryBit(scope);
        }
        return bitmap;
    }

    /**
     * Get the bit mask for a geographic scope.
     *
     * @param scope Geographic scope (apac, emea, amer, global, us, eu, etc.)
     * @return Bit mask, or 0 if unknown
     */
    public static long getGeographicBit(String scope) {
        return GEOGRAPHIC_BITS.getOrDefault(scope.toLowerCase(), 0L);
    }

    /**
     * Get combined bit mask for multiple geographic scopes.
     *
     * @param scopes List of geographic scopes
     * @return Combined bitmap
     */
    public static long getGeographicBits(Collection<String> scopes) {
        long bitmap = 0L;
        for (String scope : scopes) {
            bitmap |= getGeographicBit(scope);
        }
        return bitmap;
    }

    /**
     * Get the bit mask for a functional purpose.
     *
     * @param purpose Functional purpose (analytics, operations, marketing, etc.)
     * @return Bit mask, or 0 if unknown
     */
    public static long getPurposeBit(String purpose) {
        return PURPOSE_BITS.getOrDefault(purpose.toLowerCase(), 0L);
    }

    /**
     * Get combined bit mask for multiple purposes.
     *
     * @param purposes List of purposes
     * @return Combined bitmap
     */
    public static long getPurposeBits(Collection<String> purposes) {
        long bitmap = 0L;
        for (String purpose : purposes) {
            bitmap |= getPurposeBit(purpose);
        }
        return bitmap;
    }

    /**
     * Get the bit mask for a data type.
     *
     * @param datatype Data type (customer_data, employee_data, etc.)
     * @return Bit mask, or 0 if unknown
     */
    public static long getDatatypeBit(String datatype) {
        return DATATYPE_BITS.getOrDefault(datatype.toLowerCase(), 0L);
    }

    /**
     * Decode a bitmap into human-readable dimensions.
     *
     * @param secLo Low 64 bits of security bitmap
     * @param secHi High 64 bits of security bitmap
     * @return Map of dimension names to values
     */
    public static Map<String, List<String>> decode(long secLo, long secHi) {
        Map<String, List<String>> dimensions = new HashMap<>();

        // Sensitivity (only one should be set)
        List<String> sensitivity = new ArrayList<>();
        for (Map.Entry<String, Long> entry : SENSITIVITY_BITS.entrySet()) {
            if ((secLo & entry.getValue()) != 0) {
                sensitivity.add(entry.getKey());
            }
        }
        dimensions.put("sensitivity", sensitivity);

        // Regulatory
        List<String> regulatory = new ArrayList<>();
        for (Map.Entry<String, Long> entry : REGULATORY_BITS.entrySet()) {
            if ((secLo & entry.getValue()) != 0) {
                regulatory.add(entry.getKey());
            }
        }
        dimensions.put("regulatory", regulatory);

        // Geographic
        List<String> geographic = new ArrayList<>();
        for (Map.Entry<String, Long> entry : GEOGRAPHIC_BITS.entrySet()) {
            if ((secLo & entry.getValue()) != 0) {
                geographic.add(entry.getKey());
            }
        }
        dimensions.put("geographic", geographic);

        // Purpose
        List<String> purposes = new ArrayList<>();
        for (Map.Entry<String, Long> entry : PURPOSE_BITS.entrySet()) {
            if ((secLo & entry.getValue()) != 0) {
                purposes.add(entry.getKey());
            }
        }
        dimensions.put("purpose", purposes);

        // Data type
        List<String> datatypes = new ArrayList<>();
        for (Map.Entry<String, Long> entry : DATATYPE_BITS.entrySet()) {
            if ((secLo & entry.getValue()) != 0) {
                datatypes.add(entry.getKey());
            }
        }
        dimensions.put("datatype", datatypes);

        return dimensions;
    }

    /**
     * Get all supported dimension names.
     */
    public static Set<String> getAllSensitivityLevels() {
        return SENSITIVITY_BITS.keySet();
    }

    public static Set<String> getAllRegulatoryScopes() {
        return REGULATORY_BITS.keySet();
    }

    public static Set<String> getAllGeographicScopes() {
        return GEOGRAPHIC_BITS.keySet();
    }

    public static Set<String> getAllPurposes() {
        return PURPOSE_BITS.keySet();
    }

    public static Set<String> getAllDatatypes() {
        return DATATYPE_BITS.keySet();
    }
}
