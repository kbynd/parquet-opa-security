package io.parquet.security.examples;

import io.parquet.security.dimensions.BitmapDerivation;
import io.parquet.security.dimensions.ColumnSecurityMetadata;
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
import java.util.HashMap;
import java.util.Map;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.*;

/**
 * Example: How to characterize a raw Parquet file by adding security columns.
 *
 * This demonstrates:
 * 1. Reading raw Parquet without security columns
 * 2. Parsing column security metadata from schema
 * 3. Deriving security bitmaps using column metadata hints
 * 4. Writing secured Parquet with _sec_lo and _sec_hi columns
 *
 * Usage:
 * - As a library user, copy this pattern to build your characterization pipeline
 * - As a test, run main() to see the complete flow
 */
public class CharacterizationExample {

    /**
     * Characterize a raw Parquet file by adding security columns.
     *
     * Reads the input file, derives security bitmaps based on column metadata,
     * and writes a new file with _sec_lo and _sec_hi columns added.
     *
     * @param inputPath Raw Parquet file (without security columns)
     * @param outputPath Secured Parquet file (with security columns)
     * @throws IOException if file I/O fails
     */
    public static void characterizeFile(String inputPath, String outputPath) throws IOException {
        System.out.println("=== Characterization Pipeline ===");
        System.out.println("Input:  " + inputPath);
        System.out.println("Output: " + outputPath);
        System.out.println();

        Configuration conf = new Configuration();

        // Step 1: Read the raw file to get schema and metadata
        MessageType inputSchema;
        Map<String, String> fileMetadata;

        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), new Path(inputPath))
                .withConf(conf)
                .build()) {

            // Get schema from first record
            Group firstRow = reader.read();
            if (firstRow == null) {
                System.out.println("Input file is empty!");
                return;
            }
            inputSchema = (MessageType) firstRow.getType();

            // In a real implementation, read file-level metadata from ParquetFileReader
            // For this example, we'll extract it from the schema
            fileMetadata = extractMetadataFromSchema(inputSchema);
        }

        System.out.println("Input Schema:");
        System.out.println(inputSchema);
        System.out.println();

        // Step 2: Parse column security metadata
        Map<String, ColumnSecurityMetadata> columnMetadata =
                ColumnSecurityMetadata.parseFromFileMetadata(inputSchema, fileMetadata);

        System.out.println("Parsed Security Metadata for " + columnMetadata.size() + " columns:");
        for (Map.Entry<String, ColumnSecurityMetadata> entry : columnMetadata.entrySet()) {
            System.out.println("  " + entry.getKey() + ": " + entry.getValue());
        }
        System.out.println();

        // Step 3: Create output schema with security columns
        MessageType outputSchema = addSecurityColumns(inputSchema);

        System.out.println("Output Schema (with security columns):");
        System.out.println(outputSchema);
        System.out.println();

        // Step 4: Process file - read input, derive bitmaps, write output
        long rowsProcessed = 0;

        try (ParquetReader<Group> reader = ParquetReader.builder(new GroupReadSupport(), new Path(inputPath))
                .withConf(conf)
                .build();
             ParquetWriter<Group> writer = createWriter(new Path(outputPath), outputSchema, fileMetadata)) {

            Group inputRow;
            while ((inputRow = reader.read()) != null) {
                // Step 4a: Extract row values for bitmap derivation
                Map<String, Object> rowValues = extractRowValues(inputRow);

                // Step 4b: Derive security bitmap from column metadata
                BitmapDerivation.SecurityBitmap bitmap =
                        BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

                // Step 4c: Create output row with security columns
                Group outputRow = copyRowWithSecurity(inputRow, outputSchema, bitmap);

                // Step 4d: Write secured row
                writer.write(outputRow);

                rowsProcessed++;

                // Print first few rows for demonstration
                if (rowsProcessed <= 3) {
                    System.out.println("Row " + rowsProcessed + ":");
                    System.out.println("  Data: " + rowValues);
                    System.out.println("  _sec_lo: 0x" + Long.toHexString(bitmap.secLo));
                    System.out.println("  _sec_hi: 0x" + Long.toHexString(bitmap.secHi));
                    System.out.println("  " + bitmap);
                    System.out.println();
                }
            }
        }

        System.out.println("Characterization complete!");
        System.out.println("Processed " + rowsProcessed + " rows");
        System.out.println("Output written to: " + outputPath);
    }

    /**
     * Extract metadata from schema (simplified for example).
     * In production, read from ParquetFileReader.getFileMetaData().getKeyValueMetaData()
     */
    private static Map<String, String> extractMetadataFromSchema(MessageType schema) {
        // This is a placeholder - in real code, read from file metadata
        Map<String, String> metadata = new HashMap<>();

        // For demonstration, add some sample metadata
        // In reality, this would be stored in the Parquet file's key-value metadata
        metadata.put("column.email.security.sensitivity", "internal");
        metadata.put("column.email.security.regulatory", "pii");
        metadata.put("column.salary.security.sensitivity", "confidential");
        metadata.put("column.salary.security.regulatory", "pii,financial");
        metadata.put("column.region.security.geographic", "value_based");

        return metadata;
    }

    /**
     * Create output schema by adding _sec_lo and _sec_hi columns.
     */
    private static MessageType addSecurityColumns(MessageType inputSchema) {
        Types.MessageTypeBuilder builder = Types.buildMessage();

        // Copy all existing fields
        for (org.apache.parquet.schema.Type field : inputSchema.getFields()) {
            builder.addField(field);
        }

        // Add security columns
        builder.required(INT64).named("_sec_lo");
        builder.required(INT64).named("_sec_hi");

        return builder.named(inputSchema.getName());
    }

    /**
     * Extract row values as a map for bitmap derivation.
     */
    private static Map<String, Object> extractRowValues(Group row) {
        Map<String, Object> values = new HashMap<>();
        MessageType schema = (MessageType) row.getType();

        for (int i = 0; i < schema.getFieldCount(); i++) {
            String fieldName = schema.getFieldName(i);

            try {
                // Extract value based on type
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
                        case DOUBLE:
                            values.put(fieldName, row.getDouble(i, 0));
                            break;
                        case FLOAT:
                            values.put(fieldName, row.getFloat(i, 0));
                            break;
                        case BOOLEAN:
                            values.put(fieldName, row.getBoolean(i, 0));
                            break;
                        default:
                            values.put(fieldName, row.getValueToString(i, 0));
                    }
                }
            } catch (Exception e) {
                // Field might be null or have repetition - skip
            }
        }

        return values;
    }

    /**
     * Copy input row to output row, adding security columns.
     */
    private static Group copyRowWithSecurity(
            Group inputRow,
            MessageType outputSchema,
            BitmapDerivation.SecurityBitmap bitmap
    ) {
        SimpleGroup outputRow = new SimpleGroup(outputSchema);

        // Copy all fields from input
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
                        case DOUBLE:
                            outputRow.add(fieldName, inputRow.getDouble(i, 0));
                            break;
                        case FLOAT:
                            outputRow.add(fieldName, inputRow.getFloat(i, 0));
                            break;
                        case BOOLEAN:
                            outputRow.add(fieldName, inputRow.getBoolean(i, 0));
                            break;
                    }
                }
            } catch (Exception e) {
                // Field might be null - skip
            }
        }

        // Add security columns
        outputRow.add("_sec_lo", bitmap.secLo);
        outputRow.add("_sec_hi", bitmap.secHi);

        return outputRow;
    }

    /**
     * Create ParquetWriter with file-level metadata.
     */
    private static ParquetWriter<Group> createWriter(
            Path outputPath,
            MessageType schema,
            Map<String, String> fileMetadata
    ) throws IOException {
        Configuration conf = new Configuration();

        GroupWriteSupport writeSupport = new GroupWriteSupport();
        GroupWriteSupport.setSchema(schema, conf);

        return new ParquetWriter<>(
                outputPath,
                writeSupport,
                CompressionCodecName.SNAPPY,
                ParquetWriter.DEFAULT_BLOCK_SIZE,
                ParquetWriter.DEFAULT_PAGE_SIZE,
                ParquetWriter.DEFAULT_PAGE_SIZE,
                ParquetWriter.DEFAULT_IS_DICTIONARY_ENABLED,
                ParquetWriter.DEFAULT_IS_VALIDATING_ENABLED,
                ParquetWriter.DEFAULT_WRITER_VERSION,
                conf
        );
    }

    /**
     * Main method - creates sample data and characterizes it.
     */
    public static void main(String[] args) throws IOException {
        String inputFile = "/tmp/raw_customers.parquet";
        String outputFile = "/tmp/secured_customers.parquet";

        // Step 1: Create sample raw data
        System.out.println("Creating sample raw data...");
        createSampleRawData(inputFile);
        System.out.println("Created: " + inputFile);
        System.out.println();

        // Step 2: Characterize the file
        characterizeFile(inputFile, outputFile);
    }

    /**
     * Create sample raw Parquet file for demonstration.
     */
    private static void createSampleRawData(String filePath) throws IOException {
        MessageType schema = Types.buildMessage()
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("name")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("email")
                .required(INT64).named("salary")
                .required(BINARY).as(org.apache.parquet.schema.LogicalTypeAnnotation.stringType()).named("region")
                .named("customers");

        Configuration conf = new Configuration();
        GroupWriteSupport.setSchema(schema, conf);

        try (ParquetWriter<Group> writer = new ParquetWriter<>(
                new Path(filePath),
                new GroupWriteSupport(),
                CompressionCodecName.SNAPPY,
                ParquetWriter.DEFAULT_BLOCK_SIZE,
                ParquetWriter.DEFAULT_PAGE_SIZE,
                ParquetWriter.DEFAULT_PAGE_SIZE,
                ParquetWriter.DEFAULT_IS_DICTIONARY_ENABLED,
                ParquetWriter.DEFAULT_IS_VALIDATING_ENABLED,
                ParquetWriter.DEFAULT_WRITER_VERSION,
                conf
        )) {
            // Write sample records
            writeCustomer(writer, schema, "Alice", "alice@example.com", 120000L, "APAC");
            writeCustomer(writer, schema, "Bob", "bob@example.com", 95000L, "EMEA");
            writeCustomer(writer, schema, "Charlie", "charlie@example.com", 150000L, "AMER");
            writeCustomer(writer, schema, "Diana", "diana@example.com", 110000L, "APAC");
        }
    }

    private static void writeCustomer(
            ParquetWriter<Group> writer,
            MessageType schema,
            String name,
            String email,
            long salary,
            String region
    ) throws IOException {
        SimpleGroup group = new SimpleGroup(schema);
        group.add("name", name);
        group.add("email", email);
        group.add("salary", salary);
        group.add("region", region);
        writer.write(group);
    }
}
