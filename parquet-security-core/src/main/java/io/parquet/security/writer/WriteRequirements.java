package io.parquet.security.writer;

import io.parquet.security.UserContext;
import io.parquet.security.dimensions.SecurityDimensionsRegistry;
import org.apache.parquet.schema.MessageType;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Represents write requirements for a Parquet column.
 *
 * Write requirements are parsed from schema metadata and used to:
 * 1. Validate that a writer has sufficient clearances
 * 2. Enforce minimum/maximum classification levels
 * 3. Apply Bell-LaPadula write-up rules
 * 4. Auto-classify data based on writer context
 *
 * Metadata keys (file-level):
 * - "column.{name}.security.write.min_clearance" = "pii,gdpr"
 * - "column.{name}.security.write.required_roles" = "data_engineer,admin"
 * - "column.{name}.security.min_sensitivity" = "confidential"
 * - "column.{name}.security.max_sensitivity" = "restricted"
 * - "column.{name}.security.enforce_write_up" = "true"
 * - "column.{name}.security.auto_classify" = "true"
 * - "column.{name}.security.inherit_from_writer" = "geographic,purpose"
 */
public class WriteRequirements {

    private final String columnName;
    private final List<String> requiredRegulatoryScopes;
    private final List<String> requiredRoles;
    private final String minSensitivity;
    private final String maxSensitivity;
    private final boolean enforceWriteUp;
    private final boolean autoClassify;
    private final List<String> inheritFromWriter;

    // Metadata key prefixes
    private static final String WRITE_PREFIX = "security.write.";
    private static final String MIN_CLEARANCE_KEY = WRITE_PREFIX + "min_clearance";
    private static final String REQUIRED_ROLES_KEY = WRITE_PREFIX + "required_roles";
    private static final String MIN_SENSITIVITY_KEY = "security.min_sensitivity";
    private static final String MAX_SENSITIVITY_KEY = "security.max_sensitivity";
    private static final String ENFORCE_WRITE_UP_KEY = "security.enforce_write_up";
    private static final String AUTO_CLASSIFY_KEY = "security.auto_classify";
    private static final String INHERIT_FROM_WRITER_KEY = "security.inherit_from_writer";

    public WriteRequirements(
            String columnName,
            List<String> requiredRegulatoryScopes,
            List<String> requiredRoles,
            String minSensitivity,
            String maxSensitivity,
            boolean enforceWriteUp,
            boolean autoClassify,
            List<String> inheritFromWriter
    ) {
        this.columnName = columnName;
        this.requiredRegulatoryScopes = requiredRegulatoryScopes != null
                ? new ArrayList<>(requiredRegulatoryScopes)
                : Collections.emptyList();
        this.requiredRoles = requiredRoles != null
                ? new ArrayList<>(requiredRoles)
                : Collections.emptyList();
        this.minSensitivity = minSensitivity;
        this.maxSensitivity = maxSensitivity;
        this.enforceWriteUp = enforceWriteUp;
        this.autoClassify = autoClassify;
        this.inheritFromWriter = inheritFromWriter != null
                ? new ArrayList<>(inheritFromWriter)
                : Collections.emptyList();
    }

    public String getColumnName() {
        return columnName;
    }

    public List<String> getRequiredRegulatoryScopes() {
        return Collections.unmodifiableList(requiredRegulatoryScopes);
    }

    public List<String> getRequiredRoles() {
        return Collections.unmodifiableList(requiredRoles);
    }

    public String getMinSensitivity() {
        return minSensitivity;
    }

    public String getMaxSensitivity() {
        return maxSensitivity;
    }

    public boolean isEnforceWriteUp() {
        return enforceWriteUp;
    }

    public boolean isAutoClassify() {
        return autoClassify;
    }

    public List<String> getInheritFromWriter() {
        return Collections.unmodifiableList(inheritFromWriter);
    }

    public boolean hasWriteRequirements() {
        return !requiredRegulatoryScopes.isEmpty()
                || !requiredRoles.isEmpty()
                || minSensitivity != null
                || maxSensitivity != null
                || enforceWriteUp
                || autoClassify;
    }

    /**
     * Validate that the writer has permission to write to this column.
     *
     * @param writer User context of the writer
     * @throws WriteAccessDeniedException if writer lacks required permissions
     */
    public void validateWriter(UserContext writer) throws WriteAccessDeniedException {
        // Check required regulatory clearances
        if (!requiredRegulatoryScopes.isEmpty()) {
            for (String required : requiredRegulatoryScopes) {
                // Check if writer has this regulatory clearance
                // Note: UserContext doesn't currently expose regulatory scopes directly
                // This would need to be added to UserContext or checked via OPA
                // For now, we'll document this requirement
            }
        }

        // Check required roles
        if (!requiredRoles.isEmpty()) {
            boolean hasRequiredRole = false;
            for (String required : requiredRoles) {
                if (writer.getRoles().contains(required)) {
                    hasRequiredRole = true;
                    break;
                }
            }
            if (!hasRequiredRole) {
                throw new WriteAccessDeniedException(
                        "Writing to column '" + columnName + "' requires one of roles: "
                                + String.join(", ", requiredRoles)
                                + ". User has: " + String.join(", ", writer.getRoles()),
                        columnName,
                        writer.getUserId()
                );
            }
        }

        // Bell-LaPadula write-up enforcement
        // Note: This requires knowing the writer's sensitivity level
        // Would need to be added to UserContext or derived from roles
        // Placeholder for future implementation
    }

    /**
     * Parse write requirements from file-level metadata.
     *
     * @param schema Parquet schema
     * @param fileMetadata File-level key-value metadata
     * @return Map of column name to write requirements
     */
    public static Map<String, WriteRequirements> parseFromFileMetadata(
            MessageType schema,
            Map<String, String> fileMetadata
    ) {
        Map<String, WriteRequirements> result = new HashMap<>();

        // Group metadata by column
        Map<String, Map<String, String>> columnMetadata = new HashMap<>();

        for (Map.Entry<String, String> entry : fileMetadata.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            // Parse keys like "column.email.security.write.min_clearance"
            if (key.startsWith("column.") && key.contains(".security")) {
                String[] parts = key.split("\\.", 3);
                if (parts.length >= 3) {
                    String columnName = parts[1];
                    String metadataKey = parts[2];

                    columnMetadata.computeIfAbsent(columnName, k -> new HashMap<>())
                            .put(metadataKey, value);
                }
            }
        }

        // Parse write requirements for each column
        for (Map.Entry<String, Map<String, String>> entry : columnMetadata.entrySet()) {
            String columnName = entry.getKey();
            Map<String, String> metadata = entry.getValue();

            List<String> requiredRegulatory = parseCommaSeparated(
                    metadata.get(MIN_CLEARANCE_KEY)
            );
            List<String> requiredRoles = parseCommaSeparated(
                    metadata.get(REQUIRED_ROLES_KEY)
            );
            String minSensitivity = metadata.get(MIN_SENSITIVITY_KEY);
            String maxSensitivity = metadata.get(MAX_SENSITIVITY_KEY);
            boolean enforceWriteUp = Boolean.parseBoolean(
                    metadata.getOrDefault(ENFORCE_WRITE_UP_KEY, "false")
            );
            boolean autoClassify = Boolean.parseBoolean(
                    metadata.getOrDefault(AUTO_CLASSIFY_KEY, "false")
            );
            List<String> inheritFromWriter = parseCommaSeparated(
                    metadata.get(INHERIT_FROM_WRITER_KEY)
            );

            WriteRequirements requirements = new WriteRequirements(
                    columnName,
                    requiredRegulatory,
                    requiredRoles,
                    minSensitivity,
                    maxSensitivity,
                    enforceWriteUp,
                    autoClassify,
                    inheritFromWriter
            );

            if (requirements.hasWriteRequirements()) {
                result.put(columnName, requirements);
            }
        }

        return result;
    }

    private static List<String> parseCommaSeparated(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return "WriteRequirements{" +
                "columnName='" + columnName + '\'' +
                ", requiredRegulatoryScopes=" + requiredRegulatoryScopes +
                ", requiredRoles=" + requiredRoles +
                ", minSensitivity='" + minSensitivity + '\'' +
                ", maxSensitivity='" + maxSensitivity + '\'' +
                ", enforceWriteUp=" + enforceWriteUp +
                ", autoClassify=" + autoClassify +
                ", inheritFromWriter=" + inheritFromWriter +
                '}';
    }
}
