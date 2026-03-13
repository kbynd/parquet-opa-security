package io.parquet.security.examples;

import io.parquet.security.GroupSecurityColumnExtractor;
import io.parquet.security.SecuredParquetReader;
import io.parquet.security.SecurityPolicyProvider;
import io.parquet.security.UserContext;
import io.parquet.security.dimensions.BitmapDerivation;
import io.parquet.security.dimensions.ColumnSecurityMetadata;
import io.parquet.security.dimensions.SecurityDimensionsRegistry;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroup;
import org.apache.parquet.hadoop.ParquetReader;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.hadoop.example.GroupReadSupport;
import org.apache.parquet.hadoop.example.GroupWriteSupport;
import org.apache.parquet.hadoop.metadata.CompressionCodecName;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Types;

import java.io.IOException;
import java.util.*;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.*;

/**
 * End-to-end security example demonstrating the complete workflow.
 *
 * This example shows:
 * 1. Schema definition with security metadata
 * 2. Writing raw data without security columns
 * 3. Characterization: adding _sec_lo and _sec_hi columns
 * 4. Reading with SecuredParquetReader using different user contexts
 * 5. Demonstrating access control in action
 *
 * Workflow:
 * - Create raw employee data (name, email, salary, region, ssn)
 * - Characterize it based on column metadata
 * - Read as different users (analyst, HR admin, regional manager)
 * - Show that each user sees different rows based on permissions
 */
public class EndToEndSecurityExample {

    public static void main(String[] args) throws IOException {
        String rawFile = "/tmp/employees_raw.parquet";
        String securedFile = "/tmp/employees_secured.parquet";

        System.out.println("=".repeat(80));
        System.out.println("END-TO-END SECURITY EXAMPLE");
        System.out.println("=".repeat(80));
        System.out.println();

        // Step 1: Create raw employee data
        System.out.println("STEP 1: Creating raw employee data...");
        createRawEmployeeData(rawFile);
        System.out.println("✓ Created: " + rawFile);
        System.out.println();

        // Step 2: Define security metadata
        System.out.println("STEP 2: Defining security metadata...");
        Map<String, String> securityMetadata = defineSecurityMetadata();
        System.out.println("Column Security Rules:");
        securityMetadata.forEach((key, value) -> System.out.println("  " + key + " = " + value));
        System.out.println();

        // Step 3: Characterize the file
        System.out.println("STEP 3: Characterizing file (adding security bitmaps)...");
        characterizeFile(rawFile, securedFile, securityMetadata);
        System.out.println("✓ Created: " + securedFile);
        System.out.println();

        // Step 4: Read as different users
        System.out.println("STEP 4: Reading secured file with different user contexts...");
        System.out.println();

        // User 1: Analyst (public/internal only, no PII)
        System.out.println("-".repeat(80));
        System.out.println("USER 1: ANALYST (limited permissions)");
        System.out.println("-".repeat(80));
        UserContext analyst = new UserContext(
                "analyst@company.com",
                Arrays.asList("analyst"),
                "US",
                Collections.emptyMap()
        );
        readAsUser(securedFile, analyst);
        System.out.println();

        // User 2: HR Admin (can see PII, confidential data)
        System.out.println("-".repeat(80));
        System.out.println("USER 2: HR ADMIN (elevated permissions)");
        System.out.println("-".repeat(80));
        UserContext hrAdmin = new UserContext(
                "hradmin@company.com",
                Arrays.asList("hr_admin"),
                "US",
                Collections.emptyMap()
        );
        readAsUser(securedFile, hrAdmin);
        System.out.println();

        // User 3: APAC Manager (regional restriction)
        System.out.println("-".repeat(80));
        System.out.println("USER 3: APAC MANAGER (regional restriction)");
        System.out.println("-".repeat(80));
        UserContext apacManager = new UserContext(
                "manager@apac.company.com",
                Arrays.asList("manager", "apac_team"),
                "IN",
                Collections.emptyMap()
        );
        readAsUser(securedFile, apacManager);
        System.out.println();

        // User 4: Global Admin (unrestricted)
        System.out.println("-".repeat(80));
        System.out.println("USER 4: GLOBAL ADMIN (unrestricted)");
        System.out.println("-".repeat(80));
        UserContext globalAdmin = new UserContext(
                "admin@company.com",
                Arrays.asList("admin", "global_access"),
                "US",
                Collections.emptyMap()
        );
        readAsUser(securedFile, globalAdmin);
        System.out.println();

        System.out.println("=".repeat(80));
        System.out.println("EXAMPLE COMPLETE");
        System.out.println("=".repeat(80));
    }

    /**
     * Step 1: Create raw employee data without security columns.
     */
    private static void createRawEmployeeData(String filePath) throws IOException {
        MessageType schema = Types.buildMessage()
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("name")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("email")
                .required(INT64).named("salary")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("region")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("ssn")
                .named("employees");

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = createWriter(new Path(filePath), schema)) {
            // APAC employees
            writeEmployee(writer, schema, "Alice Chen", "alice@company.com", 120000L, "APAC", "123-45-6789");
            writeEmployee(writer, schema, "Bob Kumar", "bob@company.com", 95000L, "APAC", "234-56-7890");

            // EMEA employees
            writeEmployee(writer, schema, "Charlie Smith", "charlie@company.com", 110000L, "EMEA", "345-67-8901");
            writeEmployee(writer, schema, "Diana Jones", "diana@company.com", 150000L, "EMEA", "456-78-9012");

            // AMER employees
            writeEmployee(writer, schema, "Eve Martinez", "eve@company.com", 105000L, "AMER", "567-89-0123");
            writeEmployee(writer, schema, "Frank Johnson", "frank@company.com", 130000L, "AMER", "678-90-1234");
        }
    }

    /**
     * Step 2: Define security metadata for each column.
     */
    private static Map<String, String> defineSecurityMetadata() {
        Map<String, String> metadata = new HashMap<>();

        // Name: public, no restrictions
        metadata.put("column.name.security.sensitivity", "public");

        // Email: internal, PII
        metadata.put("column.email.security.sensitivity", "internal");
        metadata.put("column.email.security.regulatory", "pii");

        // Salary: confidential, financial
        metadata.put("column.salary.security.sensitivity", "confidential");
        metadata.put("column.salary.security.regulatory", "pii,financial");

        // Region: internal, value-based geographic
        metadata.put("column.region.security.sensitivity", "internal");
        metadata.put("column.region.security.geographic", "value_based");

        // SSN: restricted, PII + PHI
        metadata.put("column.ssn.security.sensitivity", "restricted");
        metadata.put("column.ssn.security.regulatory", "pii,phi");

        return metadata;
    }

    /**
     * Step 3: Characterize the file by adding security columns.
     */
    private static void characterizeFile(String inputPath, String outputPath,
                                         Map<String, String> metadata) throws IOException {
        Configuration conf = new Configuration();

        // Read input schema
        MessageType inputSchema;
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), new Path(inputPath))
                .withConf(conf)
                .build()) {
            Group firstRow = reader.read();
            if (firstRow == null) {
                System.out.println("Warning: Input file is empty");
                return;
            }
            inputSchema = (MessageType) firstRow.getType();
        }

        // Parse column metadata
        Map<String, ColumnSecurityMetadata> columnMetadata =
                ColumnSecurityMetadata.parseFromFileMetadata(inputSchema, metadata);

        // Create output schema with security columns
        MessageType outputSchema = addSecurityColumns(inputSchema);

        // Process file
        int rowCount = 0;
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), new Path(inputPath))
                .withConf(conf)
                .build();
             ParquetWriter<Group> writer = createWriter(new Path(outputPath), outputSchema)) {

            Group inputRow;
            while ((inputRow = reader.read()) != null) {
                // Extract row values
                Map<String, Object> rowValues = extractRowValues(inputRow);

                // Derive bitmap
                BitmapDerivation.SecurityBitmap bitmap =
                        BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

                // Copy row with security columns
                Group outputRow = copyRowWithSecurity(inputRow, outputSchema, bitmap);

                writer.write(outputRow);
                rowCount++;
            }
        }

        System.out.println("  Processed " + rowCount + " rows");
    }

    /**
     * Step 4: Read secured file with user context and show filtered results.
     */
    private static void readAsUser(String filePath, UserContext user) throws IOException {
        System.out.println("User: " + user.getUserId());
        System.out.println("Roles: " + user.getRoles());
        System.out.println("Jurisdiction: " + user.getJurisdiction());
        System.out.println();

        // Create mock security policy based on roles
        SecurityPolicyProvider policy = createMockPolicy(user);

        // Get permitted mask from policy
        io.parquet.security.PermittedMask permittedMask = policy.getPermittedMask(user);

        // Create secured reader
        Configuration conf = new Configuration();
        ParquetReader<Group> baseReader = ParquetReader.builder(new GroupReadSupport(), new Path(filePath))
                .withConf(conf)
                .build();

        GroupSecurityColumnExtractor extractor = new GroupSecurityColumnExtractor();
        SecuredParquetReader<Group> securedReader = new SecuredParquetReader<>(
                baseReader,
                permittedMask,
                extractor
        );

        // Read and display visible rows
        System.out.println("Visible rows:");
        System.out.println("-".repeat(80));

        int rowCount = 0;
        int visibleCount = 0;

        Group row;
        while ((row = securedReader.read()) != null) {
            visibleCount++;
            String name = row.getString("name", 0);
            String email = hasField(row, "email") ? row.getString("email", 0) : "[FILTERED]";
            String salary = hasField(row, "salary") ? String.valueOf(row.getLong("salary", 0)) : "[FILTERED]";
            String region = hasField(row, "region") ? row.getString("region", 0) : "[FILTERED]";
            String ssn = hasField(row, "ssn") ? row.getString("ssn", 0) : "[FILTERED]";

            System.out.printf("  %-15s %-25s $%-10s %-6s %s%n",
                    name, email, salary, region, ssn);
        }

        securedReader.close();

        System.out.println("-".repeat(80));
        System.out.println("Result: " + visibleCount + " rows visible (out of 6 total)");

        // Show statistics
        SecuredParquetReader.FilteringStats stats = securedReader.getStats();
        System.out.println("Statistics:");
        System.out.println("  Rows read: " + stats.totalRecords);
        System.out.println("  Rows filtered: " + stats.filteredRecords);
        System.out.println("  Rows returned: " + stats.passedRecords);
    }

    /**
     * Create mock security policy based on user roles.
     * In production, this would call OPA.
     */
    private static SecurityPolicyProvider createMockPolicy(UserContext user) {
        return (context) -> {
            long permittedLo = 0L;
            long permittedHi = 0L;

            // Analyst: public + internal only, no PII
            if (user.getRoles().contains("analyst")) {
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("public");
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("internal");
            }

            // HR Admin: confidential + restricted, can see PII/PHI
            if (user.getRoles().contains("hr_admin")) {
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("public");
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("internal");
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("confidential");
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("restricted");
                permittedLo |= SecurityDimensionsRegistry.getRegulatoryBit("pii");
                permittedLo |= SecurityDimensionsRegistry.getRegulatoryBit("phi");
                permittedLo |= SecurityDimensionsRegistry.getRegulatoryBit("financial");
            }

            // Manager: confidential but no restricted
            if (user.getRoles().contains("manager")) {
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("public");
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("internal");
                permittedLo |= SecurityDimensionsRegistry.getSensitivityBit("confidential");
                permittedLo |= SecurityDimensionsRegistry.getRegulatoryBit("pii");
                permittedLo |= SecurityDimensionsRegistry.getRegulatoryBit("financial");
            }

            // APAC team: only APAC geographic
            if (user.getRoles().contains("apac_team")) {
                permittedLo |= SecurityDimensionsRegistry.getGeographicBit("apac");
            }

            // Global access: all regions
            if (user.getRoles().contains("global_access")) {
                permittedLo |= SecurityDimensionsRegistry.getGeographicBit("apac");
                permittedLo |= SecurityDimensionsRegistry.getGeographicBit("emea");
                permittedLo |= SecurityDimensionsRegistry.getGeographicBit("amer");
            }

            // Admin: unrestricted
            if (user.getRoles().contains("admin")) {
                permittedLo = 0xFFFF_FFFF_FFFF_FFFFL;
                permittedHi = 0xFFFF_FFFF_FFFF_FFFFL;
            }

            return new io.parquet.security.PermittedMask(permittedLo, permittedHi);
        };
    }

    // ========== Helper Methods ==========

    private static MessageType addSecurityColumns(MessageType inputSchema) {
        Types.MessageTypeBuilder builder = Types.buildMessage();
        for (org.apache.parquet.schema.Type field : inputSchema.getFields()) {
            builder.addField(field);
        }
        builder.required(INT64).named("_sec_lo");
        builder.required(INT64).named("_sec_hi");
        return builder.named(inputSchema.getName());
    }

    private static Map<String, Object> extractRowValues(Group row) {
        Map<String, Object> values = new HashMap<>();
        MessageType schema = (MessageType) row.getType();

        for (int i = 0; i < schema.getFieldCount(); i++) {
            String fieldName = schema.getFieldName(i);
            try {
                org.apache.parquet.schema.Type fieldType = schema.getType(i);
                if (fieldType.isPrimitive()) {
                    switch (fieldType.asPrimitiveType().getPrimitiveTypeName()) {
                        case BINARY:
                            values.put(fieldName, row.getString(i, 0));
                            break;
                        case INT32:
                            values.put(fieldName, row.getInteger(i, 0));
                            break;
                        case INT64:
                            values.put(fieldName, row.getLong(i, 0));
                            break;
                    }
                }
            } catch (Exception e) {
                // Skip null fields
            }
        }
        return values;
    }

    private static Group copyRowWithSecurity(Group inputRow, MessageType outputSchema,
                                             BitmapDerivation.SecurityBitmap bitmap) {
        SimpleGroup outputRow = new SimpleGroup(outputSchema);
        MessageType inputSchema = (MessageType) inputRow.getType();

        for (int i = 0; i < inputSchema.getFieldCount(); i++) {
            String fieldName = inputSchema.getFieldName(i);
            org.apache.parquet.schema.Type fieldType = inputSchema.getType(i);

            try {
                if (fieldType.isPrimitive()) {
                    switch (fieldType.asPrimitiveType().getPrimitiveTypeName()) {
                        case BINARY:
                            outputRow.add(fieldName, inputRow.getBinary(i, 0));
                            break;
                        case INT32:
                            outputRow.add(fieldName, inputRow.getInteger(i, 0));
                            break;
                        case INT64:
                            outputRow.add(fieldName, inputRow.getLong(i, 0));
                            break;
                    }
                }
            } catch (Exception e) {
                // Skip null fields
            }
        }

        outputRow.add("_sec_lo", bitmap.secLo);
        outputRow.add("_sec_hi", bitmap.secHi);
        return outputRow;
    }

    private static ParquetWriter<Group> createWriter(Path path, MessageType schema) throws IOException {
        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);
        return new ParquetWriter<>(path, new GroupWriteSupport(),
                CompressionCodecName.SNAPPY,
                ParquetWriter.DEFAULT_BLOCK_SIZE,
                ParquetWriter.DEFAULT_PAGE_SIZE,
                ParquetWriter.DEFAULT_PAGE_SIZE,
                ParquetWriter.DEFAULT_IS_DICTIONARY_ENABLED,
                ParquetWriter.DEFAULT_IS_VALIDATING_ENABLED,
                ParquetWriter.DEFAULT_WRITER_VERSION,
                conf);
    }

    private static void writeEmployee(ParquetWriter<Group> writer, MessageType schema,
                                      String name, String email, long salary,
                                      String region, String ssn) throws IOException {
        SimpleGroup group = new SimpleGroup(schema);
        group.add("name", name);
        group.add("email", email);
        group.add("salary", salary);
        group.add("region", region);
        group.add("ssn", ssn);
        writer.write(group);
    }

    private static boolean hasField(Group row, String fieldName) {
        try {
            row.getType().getFieldIndex(fieldName);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
