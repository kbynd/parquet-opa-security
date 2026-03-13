package io.parquet.security.integration;

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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test for the characterization pipeline.
 *
 * Tests the complete flow:
 * 1. Create raw Parquet with column security metadata
 * 2. Characterize: derive bitmaps and add _sec_lo/_sec_hi columns
 * 3. Verify: read back and check bitmaps are correct
 */
class CharacterizationPipelineTest {

    @TempDir
    java.nio.file.Path tempDir;

    @Test
    void testCharacterizeFileWithColumnMetadata() throws IOException {
        // Given: Raw Parquet file with column security metadata
        Path rawFile = new Path(tempDir.resolve("raw.parquet").toString());
        Path securedFile = new Path(tempDir.resolve("secured.parquet").toString());

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.email.security.sensitivity", "internal");
        fileMetadata.put("column.email.security.regulatory", "pii,gdpr");
        fileMetadata.put("column.salary.security.sensitivity", "confidential");
        fileMetadata.put("column.salary.security.regulatory", "pii,financial");
        fileMetadata.put("column.region.security.geographic", "value_based");

        createRawCustomerData(rawFile);

        // When: Characterize the file
        characterize(rawFile, securedFile, fileMetadata);

        // Then: Verify secured file has correct bitmaps
        verifySecuredFile(securedFile, fileMetadata);
    }

    @Test
    void testCharacterizeWithValueBasedGeographic() throws IOException {
        Path rawFile = new Path(tempDir.resolve("raw_geo.parquet").toString());
        Path securedFile = new Path(tempDir.resolve("secured_geo.parquet").toString());

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.data.security.sensitivity", "internal");
        fileMetadata.put("column.country.security.geographic", "value_based");

        // Create data with different countries
        createGeoData(rawFile);

        // Characterize
        characterize(rawFile, securedFile, fileMetadata);

        // Verify each row has correct geographic bit based on country value
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), securedFile)
                .build()) {

            Group row1 = reader.read();
            assertNotNull(row1);
            assertEquals("IN", row1.getString("country", 0));
            long secLo1 = row1.getLong("_sec_lo", 0);
            Map<String, List<String>> dims1 = SecurityDimensionsRegistry.decode(secLo1, 0L);
            assertTrue(dims1.get("geographic").contains("in"), "Row 1 should have IN geographic bit");

            Group row2 = reader.read();
            assertNotNull(row2);
            assertEquals("US", row2.getString("country", 0));
            long secLo2 = row2.getLong("_sec_lo", 0);
            Map<String, List<String>> dims2 = SecurityDimensionsRegistry.decode(secLo2, 0L);
            assertTrue(dims2.get("geographic").contains("us"), "Row 2 should have US geographic bit");
        }
    }

    @Test
    void testCharacterizeWithMultipleSecurityDimensions() throws IOException {
        Path rawFile = new Path(tempDir.resolve("raw_multi.parquet").toString());
        Path securedFile = new Path(tempDir.resolve("secured_multi.parquet").toString());

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.ssn.security.sensitivity", "restricted");
        fileMetadata.put("column.ssn.security.regulatory", "pii,phi");
        fileMetadata.put("column.ssn.security.purpose", "audit");
        fileMetadata.put("column.ssn.security.datatype", "employee_data");

        createSsnData(rawFile);

        characterize(rawFile, securedFile, fileMetadata);

        // Verify all dimensions present
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), securedFile)
                .build()) {

            Group row = reader.read();
            assertNotNull(row);

            long secLo = row.getLong("_sec_lo", 0);
            Map<String, List<String>> dims = SecurityDimensionsRegistry.decode(secLo, 0L);

            assertTrue(dims.get("sensitivity").contains("restricted"), "Should have restricted sensitivity");
            assertTrue(dims.get("regulatory").contains("pii"), "Should have PII regulatory");
            assertTrue(dims.get("regulatory").contains("phi"), "Should have PHI regulatory");
            assertTrue(dims.get("purpose").contains("audit"), "Should have audit purpose");
            assertTrue(dims.get("datatype").contains("employee_data"), "Should have employee_data type");
        }
    }

    @Test
    void testCharacterizeEmptyFile() throws IOException {
        Path rawFile = new Path(tempDir.resolve("empty.parquet").toString());
        Path securedFile = new Path(tempDir.resolve("empty_secured.parquet").toString());

        Map<String, String> fileMetadata = new HashMap<>();

        createEmptyFile(rawFile);

        characterize(rawFile, securedFile, fileMetadata);

        // Verify output is also empty
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), securedFile)
                .build()) {
            assertNull(reader.read(), "Output file should be empty");
        }
    }

    // ========== Helper Methods ==========

    private void characterize(Path input, Path output, Map<String, String> fileMetadata) throws IOException {
        Configuration conf = new Configuration();

        // Read input schema
        MessageType inputSchema;
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), input)
                .withConf(conf)
                .build()) {
            Group firstRow = reader.read();
            if (firstRow == null) {
                // Empty file - just create empty output
                MessageType emptySchema = Types.buildMessage()
                        .required(INT64).named("_sec_lo")
                        .required(INT64).named("_sec_hi")
                        .named("empty");
                createEmptySecuredFile(output, emptySchema);
                return;
            }
            inputSchema = (MessageType) firstRow.getType();
        }

        // Parse column metadata
        Map<String, ColumnSecurityMetadata> columnMetadata =
                ColumnSecurityMetadata.parseFromFileMetadata(inputSchema, fileMetadata);

        // Create output schema with security columns
        MessageType outputSchema = addSecurityColumns(inputSchema);

        // Process file
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), input)
                .withConf(conf)
                .build();
             ParquetWriter<Group> writer = createWriter(output, outputSchema)) {

            Group inputRow;
            while ((inputRow = reader.read()) != null) {
                Map<String, Object> rowValues = extractRowValues(inputRow);
                BitmapDerivation.SecurityBitmap bitmap =
                        BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);
                Group outputRow = copyRowWithSecurity(inputRow, outputSchema, bitmap);
                writer.write(outputRow);
            }
        }
    }

    private void verifySecuredFile(Path securedFile, Map<String, String> fileMetadata) throws IOException {
        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), securedFile)
                .build()) {

            // Read first row (Alice, APAC)
            Group row1 = reader.read();
            assertNotNull(row1);
            assertEquals("Alice", row1.getString("name", 0));

            long secLo1 = row1.getLong("_sec_lo", 0);
            long secHi1 = row1.getLong("_sec_hi", 0);

            Map<String, List<String>> dims1 = SecurityDimensionsRegistry.decode(secLo1, secHi1);

            // Verify dimensions
            assertTrue(dims1.get("sensitivity").contains("confidential"),
                    "Should have confidential (highest between internal email and confidential salary)");
            assertTrue(dims1.get("regulatory").contains("pii"), "Should have PII from email and salary");
            assertTrue(dims1.get("regulatory").contains("gdpr"), "Should have GDPR from email");
            assertTrue(dims1.get("regulatory").contains("financial"), "Should have financial from salary");
            assertTrue(dims1.get("geographic").contains("apac"), "Should have APAC from region value");

            // Read second row (Bob, EMEA)
            Group row2 = reader.read();
            assertNotNull(row2);
            assertEquals("Bob", row2.getString("name", 0));

            long secLo2 = row2.getLong("_sec_lo", 0);
            Map<String, List<String>> dims2 = SecurityDimensionsRegistry.decode(secLo2, 0L);
            assertTrue(dims2.get("geographic").contains("emea"), "Should have EMEA from region value");
        }
    }

    private MessageType addSecurityColumns(MessageType inputSchema) {
        Types.MessageTypeBuilder builder = Types.buildMessage();
        for (org.apache.parquet.schema.Type field : inputSchema.getFields()) {
            builder.addField(field);
        }
        builder.required(INT64).named("_sec_lo");
        builder.required(INT64).named("_sec_hi");
        return builder.named(inputSchema.getName());
    }

    private Map<String, Object> extractRowValues(Group row) {
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

    private Group copyRowWithSecurity(Group inputRow, MessageType outputSchema,
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

    private ParquetWriter<Group> createWriter(Path path, MessageType schema) throws IOException {
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

    private void createRawCustomerData(Path path) throws IOException {
        MessageType schema = Types.buildMessage()
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("name")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("email")
                .required(INT64).named("salary")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("region")
                .named("customers");

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = createWriter(path, schema)) {
            writeCustomer(writer, schema, "Alice", "alice@example.com", 120000L, "APAC");
            writeCustomer(writer, schema, "Bob", "bob@example.com", 95000L, "EMEA");
            writeCustomer(writer, schema, "Charlie", "charlie@example.com", 150000L, "AMER");
        }
    }

    private void writeCustomer(ParquetWriter<Group> writer, MessageType schema,
                                String name, String email, long salary, String region) throws IOException {
        SimpleGroup group = new SimpleGroup(schema);
        group.add("name", name);
        group.add("email", email);
        group.add("salary", salary);
        group.add("region", region);
        writer.write(group);
    }

    private void createGeoData(Path path) throws IOException {
        MessageType schema = Types.buildMessage()
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("data")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("country")
                .named("geo_data");

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = createWriter(path, schema)) {
            SimpleGroup row1 = new SimpleGroup(schema);
            row1.add("data", "India data");
            row1.add("country", "IN");
            writer.write(row1);

            SimpleGroup row2 = new SimpleGroup(schema);
            row2.add("data", "US data");
            row2.add("country", "US");
            writer.write(row2);
        }
    }

    private void createSsnData(Path path) throws IOException {
        MessageType schema = Types.buildMessage()
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("ssn")
                .named("ssn_data");

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = createWriter(path, schema)) {
            SimpleGroup row = new SimpleGroup(schema);
            row.add("ssn", "123-45-6789");
            writer.write(row);
        }
    }

    private void createEmptyFile(Path path) throws IOException {
        MessageType schema = Types.buildMessage()
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("data")
                .named("empty");

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = createWriter(path, schema)) {
            // Don't write any rows
        }
    }

    private void createEmptySecuredFile(Path path, MessageType schema) throws IOException {
        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = createWriter(path, schema)) {
            // Don't write any rows
        }
    }
}
