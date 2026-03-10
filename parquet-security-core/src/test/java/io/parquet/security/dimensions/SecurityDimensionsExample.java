package io.parquet.security.dimensions;

import java.util.*;

/**
 * Complete example demonstrating the security dimensions system.
 *
 * This example shows:
 * 1. Creating column metadata
 * 2. Deriving row bitmaps from metadata + row values
 * 3. Validating and decoding bitmaps
 * 4. Understanding what each dimension contributes
 *
 * Run this class to see the security dimensions in action.
 */
public class SecurityDimensionsExample {

    public static void main(String[] args) {
        System.out.println("=".repeat(80));
        System.out.println("Security Dimensions Example");
        System.out.println("=".repeat(80));
        System.out.println();

        // Example 1: Customer data with value-based geographic
        example1_CustomerData();
        System.out.println();

        // Example 2: Employee HR data with multiple sensitivity levels
        example2_EmployeeData();
        System.out.println();

        // Example 3: Healthcare data with PHI
        example3_HealthcareData();
        System.out.println();

        // Example 4: Column-by-column contribution
        example4_ColumnContribution();
    }

    private static void example1_CustomerData() {
        System.out.println("Example 1: Customer Data with Geographic Restrictions");
        System.out.println("-".repeat(80));

        // Define column metadata (from Parquet schema)
        Map<String, ColumnSecurityMetadata> columnMetadata = new HashMap<>();

        // customer_id: internal, customer_data
        columnMetadata.put("customer_id", new ColumnSecurityMetadata(
                "customer_id",
                "internal",
                Collections.emptyList(),
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                "customer_data",
                "auto"
        ));

        // email: internal, pii+gdpr, customer_data
        columnMetadata.put("email", new ColumnSecurityMetadata(
                "email",
                "internal",
                Arrays.asList("pii", "gdpr"),
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                "customer_data",
                "auto"
        ));

        // region: value-based geographic
        columnMetadata.put("region", new ColumnSecurityMetadata(
                "region",
                null,
                Collections.emptyList(),
                Collections.emptyList(),
                true, // value-based!
                Collections.emptyList(),
                null,
                "auto"
        ));

        // Row data
        Map<String, Object> row = new HashMap<>();
        row.put("customer_id", "C123");
        row.put("email", "alice@example.com");
        row.put("region", "APAC");

        // Derive bitmap
        BitmapDerivation.SecurityBitmap bitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, row);

        // Display results
        System.out.println("Row values:");
        System.out.println("  customer_id: " + row.get("customer_id"));
        System.out.println("  email: " + row.get("email"));
        System.out.println("  region: " + row.get("region"));
        System.out.println();

        System.out.println(BitmapDerivation.describe(bitmap));
        System.out.println();

        // Validate
        List<String> errors = BitmapDerivation.validate(bitmap);
        if (errors.isEmpty()) {
            System.out.println("✅ Bitmap is valid");
        } else {
            System.out.println("❌ Validation errors:");
            errors.forEach(err -> System.out.println("   " + err));
        }

        System.out.println();
        System.out.println("Access requirements:");
        System.out.println("  - Sensitivity: internal or higher");
        System.out.println("  - Regulatory: pii AND gdpr clearances required");
        System.out.println("  - Geographic: apac access (or global)");
    }

    private static void example2_EmployeeData() {
        System.out.println("Example 2: Employee HR Data with Multiple Sensitivity Levels");
        System.out.println("-".repeat(80));

        // Define column metadata
        Map<String, ColumnSecurityMetadata> columnMetadata = new HashMap<>();

        // employee_id: internal
        columnMetadata.put("employee_id", new ColumnSecurityMetadata(
                "employee_id",
                "internal",
                Collections.emptyList(),
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                "employee_data",
                "auto"
        ));

        // salary: CONFIDENTIAL, pii+financial, operations+audit
        columnMetadata.put("salary", new ColumnSecurityMetadata(
                "salary",
                "confidential",
                Arrays.asList("pii", "financial"),
                Collections.emptyList(),
                false,
                Arrays.asList("operations", "audit"),
                "employee_data",
                "auto"
        ));

        // performance_review: CONFIDENTIAL, pii, operations
        columnMetadata.put("performance_review", new ColumnSecurityMetadata(
                "performance_review",
                "confidential",
                Arrays.asList("pii"),
                Collections.emptyList(),
                false,
                Arrays.asList("operations"),
                "employee_data",
                "auto"
        ));

        // Row data
        Map<String, Object> row = new HashMap<>();
        row.put("employee_id", "E456");
        row.put("salary", 120000L);
        row.put("performance_review", "Exceeds expectations");

        // Derive bitmap
        BitmapDerivation.SecurityBitmap bitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, row);

        System.out.println("Row values:");
        System.out.println("  employee_id: " + row.get("employee_id"));
        System.out.println("  salary: " + row.get("salary"));
        System.out.println("  performance_review: " + row.get("performance_review"));
        System.out.println();

        System.out.println(BitmapDerivation.describe(bitmap));
        System.out.println();

        // Note about sensitivity
        System.out.println("Note: Multiple columns had different sensitivity levels:");
        System.out.println("  - employee_id: internal");
        System.out.println("  - salary: confidential");
        System.out.println("  - performance_review: confidential");
        System.out.println("  → Row uses HIGHEST level: confidential");
        System.out.println();

        System.out.println("Access requirements:");
        System.out.println("  - Sensitivity: confidential or higher");
        System.out.println("  - Regulatory: pii AND financial clearances required");
        System.out.println("  - Purpose: operations OR audit purpose required");
    }

    private static void example3_HealthcareData() {
        System.out.println("Example 3: Healthcare Data with PHI");
        System.out.println("-".repeat(80));

        // Define column metadata
        Map<String, ColumnSecurityMetadata> columnMetadata = new HashMap<>();

        // patient_id: internal, phi
        columnMetadata.put("patient_id", new ColumnSecurityMetadata(
                "patient_id",
                "internal",
                Arrays.asList("phi"),
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                "health_data",
                "auto"
        ));

        // diagnosis: RESTRICTED, phi, operations+research
        columnMetadata.put("diagnosis", new ColumnSecurityMetadata(
                "diagnosis",
                "restricted",
                Arrays.asList("phi"),
                Collections.emptyList(),
                false,
                Arrays.asList("operations", "research"),
                "health_data",
                "auto"
        ));

        // country: value-based geographic
        columnMetadata.put("country", new ColumnSecurityMetadata(
                "country",
                null,
                Collections.emptyList(),
                Collections.emptyList(),
                true,
                Collections.emptyList(),
                null,
                "auto"
        ));

        // Row data
        Map<String, Object> row = new HashMap<>();
        row.put("patient_id", "P789");
        row.put("diagnosis", "Type 2 Diabetes");
        row.put("country", "US");

        // Derive bitmap
        BitmapDerivation.SecurityBitmap bitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, row);

        System.out.println("Row values:");
        System.out.println("  patient_id: " + row.get("patient_id"));
        System.out.println("  diagnosis: " + row.get("diagnosis"));
        System.out.println("  country: " + row.get("country"));
        System.out.println();

        System.out.println(BitmapDerivation.describe(bitmap));
        System.out.println();

        System.out.println("Access requirements:");
        System.out.println("  - Sensitivity: restricted (highest level!)");
        System.out.println("  - Regulatory: phi clearance required");
        System.out.println("  - Geographic: us access (or amer, or global)");
        System.out.println("  - Purpose: operations OR research purpose required");
    }

    private static void example4_ColumnContribution() {
        System.out.println("Example 4: Column-by-Column Contribution Analysis");
        System.out.println("-".repeat(80));

        // Create metadata for a row with multiple columns
        Map<String, ColumnSecurityMetadata> columnMetadata = new HashMap<>();

        columnMetadata.put("name", new ColumnSecurityMetadata(
                "name",
                "internal",
                Collections.emptyList(),
                Collections.emptyList(),
                false,
                Collections.emptyList(),
                "customer_data",
                "auto"
        ));

        columnMetadata.put("email", new ColumnSecurityMetadata(
                "email",
                "internal",
                Arrays.asList("pii", "gdpr"),
                Collections.emptyList(),
                false,
                Arrays.asList("analytics"),
                "customer_data",
                "auto"
        ));

        columnMetadata.put("salary", new ColumnSecurityMetadata(
                "salary",
                "confidential",
                Arrays.asList("financial"),
                Collections.emptyList(),
                false,
                Arrays.asList("operations"),
                "employee_data",
                "auto"
        ));

        columnMetadata.put("region", new ColumnSecurityMetadata(
                "region",
                null,
                Collections.emptyList(),
                Collections.emptyList(),
                true,
                Collections.emptyList(),
                null,
                "auto"
        ));

        Map<String, Object> rowValues = new HashMap<>();
        rowValues.put("name", "Alice");
        rowValues.put("email", "alice@example.com");
        rowValues.put("salary", 120000L);
        rowValues.put("region", "APAC");

        System.out.println("Analyzing column contributions:");
        System.out.println();

        for (Map.Entry<String, ColumnSecurityMetadata> entry : columnMetadata.entrySet()) {
            String columnName = entry.getKey();
            ColumnSecurityMetadata metadata = entry.getValue();
            Object value = rowValues.get(columnName);

            BitmapDerivation.SecurityBitmap columnBitmap =
                    BitmapDerivation.deriveColumnBitmap(metadata, value);

            System.out.println("Column: " + columnName);
            System.out.println("  Value: " + value);

            Map<String, List<String>> dims =
                    SecurityDimensionsRegistry.decode(columnBitmap.secLo, columnBitmap.secHi);

            if (!dims.get("sensitivity").isEmpty()) {
                System.out.println("  Sensitivity: " + dims.get("sensitivity"));
            }
            if (!dims.get("regulatory").isEmpty()) {
                System.out.println("  Regulatory: " + dims.get("regulatory"));
            }
            if (!dims.get("geographic").isEmpty()) {
                System.out.println("  Geographic: " + dims.get("geographic"));
            }
            if (!dims.get("purpose").isEmpty()) {
                System.out.println("  Purpose: " + dims.get("purpose"));
            }
            if (!dims.get("datatype").isEmpty()) {
                System.out.println("  DataType: " + dims.get("datatype"));
            }
            System.out.println();
        }

        // Now show combined bitmap
        BitmapDerivation.SecurityBitmap combinedBitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

        System.out.println("Combined row bitmap:");
        System.out.println(BitmapDerivation.describe(combinedBitmap));
        System.out.println();

        System.out.println("Key observations:");
        System.out.println("  - Sensitivity uses HIGHEST level (confidential from salary)");
        System.out.println("  - Regulatory ACCUMULATES (pii, gdpr, financial)");
        System.out.println("  - Geographic from region VALUE (APAC)");
        System.out.println("  - Purpose ACCUMULATES (analytics, operations)");
        System.out.println("  - DataType ACCUMULATES (customer_data, employee_data)");
    }
}
