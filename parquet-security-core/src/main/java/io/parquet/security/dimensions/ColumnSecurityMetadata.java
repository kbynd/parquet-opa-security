package io.parquet.security.dimensions;

import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Type;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Parses and manages security metadata from Parquet column definitions.
 *
 * Reads key-value metadata attached to columns:
 * - "security.sensitivity": Sensitivity level (public, internal, confidential, restricted)
 * - "security.regulatory": Comma-separated regulatory scopes (pii, phi, financial, etc.)
 * - "security.geographic": Geographic scopes or "value_based" for row-value derivation
 * - "security.purpose": Comma-separated purposes (analytics, operations, etc.)
 * - "security.datatype": Data type classification (customer_data, employee_data, etc.)
 * - "security.derivation": How metadata was derived (auto, manual, ml)
 *
 * Example column metadata:
 * {
 *   "security.sensitivity": "confidential",
 *   "security.regulatory": "pii,financial",
 *   "security.datatype": "employee_data",
 *   "security.derivation": "auto"
 * }
 */
public class ColumnSecurityMetadata {

    public static final String METADATA_KEY_SENSITIVITY = "security.sensitivity";
    public static final String METADATA_KEY_REGULATORY = "security.regulatory";
    public static final String METADATA_KEY_GEOGRAPHIC = "security.geographic";
    public static final String METADATA_KEY_PURPOSE = "security.purpose";
    public static final String METADATA_KEY_DATATYPE = "security.datatype";
    public static final String METADATA_KEY_DERIVATION = "security.derivation";

    public static final String VALUE_BASED_MARKER = "value_based";

    private final String columnName;
    private final String sensitivity;
    private final List<String> regulatoryScopes;
    private final List<String> geographicScopes;
    private final boolean geographicValueBased;
    private final List<String> purposes;
    private final String datatype;
    private final String derivation;

    // Package-private constructor for testing
    ColumnSecurityMetadata(
            String columnName,
            String sensitivity,
            List<String> regulatoryScopes,
            List<String> geographicScopes,
            boolean geographicValueBased,
            List<String> purposes,
            String datatype,
            String derivation
    ) {
        this.columnName = columnName;
        this.sensitivity = sensitivity;
        this.regulatoryScopes = regulatoryScopes;
        this.geographicScopes = geographicScopes;
        this.geographicValueBased = geographicValueBased;
        this.purposes = purposes;
        this.datatype = datatype;
        this.derivation = derivation;
    }

    public String getColumnName() {
        return columnName;
    }

    public String getSensitivity() {
        return sensitivity;
    }

    public List<String> getRegulatoryScopes() {
        return regulatoryScopes;
    }

    public List<String> getGeographicScopes() {
        return geographicScopes;
    }

    public boolean isGeographicValueBased() {
        return geographicValueBased;
    }

    public List<String> getPurposes() {
        return purposes;
    }

    public String getDatatype() {
        return datatype;
    }

    public String getDerivation() {
        return derivation;
    }

    public boolean hasSecurityMetadata() {
        return sensitivity != null
                || !regulatoryScopes.isEmpty()
                || !geographicScopes.isEmpty()
                || geographicValueBased
                || !purposes.isEmpty()
                || datatype != null;
    }

    /**
     * Parse security metadata from a Parquet column type.
     *
     * @param columnType Parquet column type with metadata
     * @return Parsed security metadata
     */
    public static ColumnSecurityMetadata parse(Type columnType) {
        String columnName = columnType.getName();
        Map<String, String> keyValueMetadata = new HashMap<>();

        // Extract metadata as strings
        if (columnType.getLogicalTypeAnnotation() != null
                && columnType.getLogicalTypeAnnotation().toOriginalType() != null) {
            // Metadata is stored differently in different Parquet versions
            // Try to access via reflection or API as available
        }

        // For now, we'll use a simpler approach - metadata should be in the field's metadata map
        // This will be populated when we read the schema
        org.apache.parquet.schema.Types.MessageTypeBuilder builder;

        // Parse metadata from the type's metadata map if available
        // Note: Parquet metadata is stored as binary key-value pairs
        // We'll need to handle this when actually reading files

        String sensitivity = keyValueMetadata.get(METADATA_KEY_SENSITIVITY);
        List<String> regulatory = parseCommaSeparated(keyValueMetadata.get(METADATA_KEY_REGULATORY));
        String geographic = keyValueMetadata.get(METADATA_KEY_GEOGRAPHIC);
        List<String> purposes = parseCommaSeparated(keyValueMetadata.get(METADATA_KEY_PURPOSE));
        String datatype = keyValueMetadata.get(METADATA_KEY_DATATYPE);
        String derivation = keyValueMetadata.get(METADATA_KEY_DERIVATION);

        boolean geographicValueBased = VALUE_BASED_MARKER.equalsIgnoreCase(geographic);
        List<String> geographicScopes = geographicValueBased
                ? Collections.emptyList()
                : parseCommaSeparated(geographic);

        return new ColumnSecurityMetadata(
                columnName,
                sensitivity,
                regulatory,
                geographicScopes,
                geographicValueBased,
                purposes,
                datatype,
                derivation
        );
    }

    /**
     * Parse security metadata from all columns in a Parquet schema.
     *
     * @param schema Parquet message type (schema)
     * @return Map of column name to security metadata
     */
    public static Map<String, ColumnSecurityMetadata> parseSchema(MessageType schema) {
        Map<String, ColumnSecurityMetadata> result = new HashMap<>();

        for (Type field : schema.getFields()) {
            ColumnSecurityMetadata metadata = parse(field);
            if (metadata.hasSecurityMetadata()) {
                result.put(field.getName(), metadata);
            }
        }

        return result;
    }

    /**
     * Parse security metadata from file-level key-value metadata.
     * This is more reliable than column-level metadata in current Parquet implementations.
     *
     * @param schema Parquet schema
     * @param fileMetadata File-level key-value metadata (binary keys/values)
     * @return Map of column name to security metadata
     */
    public static Map<String, ColumnSecurityMetadata> parseFromFileMetadata(
            MessageType schema,
            Map<String, String> fileMetadata
    ) {
        Map<String, ColumnSecurityMetadata> result = new HashMap<>();

        // File metadata uses keys like: "column.email.security.sensitivity" = "confidential"
        Map<String, Map<String, String>> columnMetadata = new HashMap<>();

        for (Map.Entry<String, String> entry : fileMetadata.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            // Parse keys like "column.email.security.sensitivity"
            if (key.startsWith("column.") && key.contains(".security.")) {
                String[] parts = key.split("\\.", 4);
                if (parts.length >= 4) {
                    String columnName = parts[1];
                    String securityKey = "security." + parts[3];

                    columnMetadata.computeIfAbsent(columnName, k -> new HashMap<>())
                            .put(securityKey, value);
                }
            }
        }

        // Build ColumnSecurityMetadata for each column
        for (Map.Entry<String, Map<String, String>> entry : columnMetadata.entrySet()) {
            String columnName = entry.getKey();
            Map<String, String> metadata = entry.getValue();

            String sensitivity = metadata.get(METADATA_KEY_SENSITIVITY);
            List<String> regulatory = parseCommaSeparated(metadata.get(METADATA_KEY_REGULATORY));
            String geographic = metadata.get(METADATA_KEY_GEOGRAPHIC);
            List<String> purposes = parseCommaSeparated(metadata.get(METADATA_KEY_PURPOSE));
            String datatype = metadata.get(METADATA_KEY_DATATYPE);
            String derivation = metadata.get(METADATA_KEY_DERIVATION);

            boolean geographicValueBased = VALUE_BASED_MARKER.equalsIgnoreCase(geographic);
            List<String> geographicScopes = geographicValueBased
                    ? Collections.emptyList()
                    : parseCommaSeparated(geographic);

            ColumnSecurityMetadata colMeta = new ColumnSecurityMetadata(
                    columnName,
                    sensitivity,
                    regulatory,
                    geographicScopes,
                    geographicValueBased,
                    purposes,
                    datatype,
                    derivation
            );

            if (colMeta.hasSecurityMetadata()) {
                result.put(columnName, colMeta);
            }
        }

        return result;
    }

    /**
     * Parse comma-separated values.
     */
    private static List<String> parseCommaSeparated(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<String> result = new ArrayList<>();
        for (String part : value.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed.toLowerCase());
            }
        }
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ColumnSecurityMetadata{");
        sb.append("column=").append(columnName);

        if (sensitivity != null) {
            sb.append(", sensitivity=").append(sensitivity);
        }
        if (!regulatoryScopes.isEmpty()) {
            sb.append(", regulatory=").append(regulatoryScopes);
        }
        if (geographicValueBased) {
            sb.append(", geographic=value_based");
        } else if (!geographicScopes.isEmpty()) {
            sb.append(", geographic=").append(geographicScopes);
        }
        if (!purposes.isEmpty()) {
            sb.append(", purposes=").append(purposes);
        }
        if (datatype != null) {
            sb.append(", datatype=").append(datatype);
        }
        if (derivation != null) {
            sb.append(", derivation=").append(derivation);
        }

        sb.append("}");
        return sb.toString();
    }
}
