package io.parquet.security.writer;

import io.parquet.security.UserContext;
import io.parquet.security.audit.NoOpAuditHandler;
import io.parquet.security.audit.WriteAuditEventImpl;
import io.parquet.security.audit.WriteAuditHandler;
import io.parquet.security.dimensions.BitmapDerivation;
import io.parquet.security.dimensions.ColumnSecurityMetadata;
import io.parquet.security.dimensions.SecurityDimensionsRegistry;
import org.apache.parquet.hadoop.ParquetWriter;
import org.apache.parquet.schema.MessageType;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Secured wrapper around ParquetWriter that enforces write requirements.
 *
 * This writer:
 * 1. Validates writer has required clearances/roles on construction
 * 2. Derives security bitmaps for each row (from metadata + auto-classification)
 * 3. Validates bitmaps meet minimum/maximum classification requirements
 * 4. Optionally audits all write operations
 * 5. Delegates to underlying ParquetWriter
 *
 * Usage:
 * <pre>
 * UserContext writer = new UserContext("user@example.com",
 *     List.of("data_engineer"), "US", Map.of());
 *
 * Map&lt;String, String&gt; fileMetadata = extractMetadata(schema);
 *
 * try (SecuredParquetWriter writer = new SecuredParquetWriter(
 *     delegate, writer, schema, fileMetadata
 * )) {
 *     writer.write(record);
 * }
 * </pre>
 *
 * Note: This is a validation and audit wrapper. It does NOT automatically
 * add _sec_lo and _sec_hi columns to records - that must be done by the
 * caller based on the derived bitmap.
 *
 * @param <T> Record type (Group, GenericRecord, etc.)
 */
public class SecuredParquetWriter<T> implements Closeable {

    private final ParquetWriter<T> delegate;
    private final UserContext writerContext;
    private final Map<String, WriteRequirements> writeRequirements;
    private final Map<String, ColumnSecurityMetadata> columnMetadata;
    private final WriteAuditHandler auditHandler;
    private final String filePath;
    private long rowsWritten = 0;

    /**
     * Create a secured writer with no auditing (default).
     *
     * @param delegate Underlying ParquetWriter
     * @param writerContext User context of the writer
     * @param schema Parquet schema
     * @param fileMetadata File-level key-value metadata
     * @throws WriteAccessDeniedException if writer lacks required permissions
     */
    public SecuredParquetWriter(
            ParquetWriter<T> delegate,
            UserContext writerContext,
            MessageType schema,
            Map<String, String> fileMetadata
    ) throws WriteAccessDeniedException {
        this(delegate, writerContext, schema, fileMetadata, new NoOpAuditHandler(), "unknown");
    }

    /**
     * Create a secured writer with custom audit handler.
     *
     * @param delegate Underlying ParquetWriter
     * @param writerContext User context of the writer
     * @param schema Parquet schema
     * @param fileMetadata File-level key-value metadata
     * @param auditHandler Audit handler (use NoOpAuditHandler for no auditing)
     * @param filePath Path to file being written (for audit events)
     * @throws WriteAccessDeniedException if writer lacks required permissions
     */
    public SecuredParquetWriter(
            ParquetWriter<T> delegate,
            UserContext writerContext,
            MessageType schema,
            Map<String, String> fileMetadata,
            WriteAuditHandler auditHandler,
            String filePath
    ) throws WriteAccessDeniedException {
        this.delegate = delegate;
        this.writerContext = writerContext;
        this.filePath = filePath;
        this.auditHandler = auditHandler != null ? auditHandler : new NoOpAuditHandler();

        // Parse metadata
        this.writeRequirements = WriteRequirements.parseFromFileMetadata(schema, fileMetadata);
        this.columnMetadata = ColumnSecurityMetadata.parseFromFileMetadata(schema, fileMetadata);

        // Validate writer has permission to write to this schema
        validateWriterAccess();
    }

    /**
     * Validate that writer has permission to write to this schema.
     *
     * Checks all columns with write requirements to ensure writer has
     * necessary clearances and roles.
     *
     * @throws WriteAccessDeniedException if validation fails
     */
    private void validateWriterAccess() throws WriteAccessDeniedException {
        for (Map.Entry<String, WriteRequirements> entry : writeRequirements.entrySet()) {
            String columnName = entry.getKey();
            WriteRequirements requirements = entry.getValue();

            try {
                requirements.validateWriter(writerContext);
            } catch (WriteAccessDeniedException e) {
                // Audit the denial
                auditHandler.onWriteEvent(new WriteAuditEventImpl(
                        writerContext.getUserId(),
                        filePath,
                        columnName,
                        "schema_access_denied",
                        e.getMessage(),
                        System.currentTimeMillis()
                ));
                throw e;
            }
        }
    }

    /**
     * Derive security bitmap for a row.
     *
     * This combines:
     * 1. Metadata-driven classification (from column security metadata)
     * 2. Auto-classification (from writer context, if enabled)
     *
     * @param rowValues Map of column name to value
     * @return Derived security bitmap
     */
    public BitmapDerivation.SecurityBitmap deriveBitmap(Map<String, Object> rowValues) {
        // Derive base bitmap from metadata
        BitmapDerivation.SecurityBitmap bitmap =
                BitmapDerivation.deriveRowBitmap(columnMetadata, rowValues);

        // Apply auto-classification from writer context
        bitmap = applyAutoClassification(bitmap);

        return bitmap;
    }

    /**
     * Apply auto-classification based on writer context.
     *
     * For columns marked with auto_classify=true, this adds classification
     * based on the writer's attributes:
     * - geographic: Writer's jurisdiction
     * - purpose: Derived from writer's roles
     *
     * @param baseBitmap Base bitmap from metadata
     * @return Enhanced bitmap with auto-classification
     */
    private BitmapDerivation.SecurityBitmap applyAutoClassification(
            BitmapDerivation.SecurityBitmap baseBitmap
    ) {
        long secLo = baseBitmap.secLo;
        long secHi = baseBitmap.secHi;

        for (Map.Entry<String, WriteRequirements> entry : writeRequirements.entrySet()) {
            WriteRequirements req = entry.getValue();

            if (!req.isAutoClassify()) {
                continue;
            }

            // Inherit from writer context
            for (String dimension : req.getInheritFromWriter()) {
                switch (dimension.toLowerCase()) {
                    case "geographic":
                        // Add writer's jurisdiction to geographic bits
                        if (writerContext.getJurisdiction() != null) {
                            secLo |= SecurityDimensionsRegistry.getGeographicBit(
                                    writerContext.getJurisdiction()
                            );
                        }
                        break;

                    case "purpose":
                        // Derive purpose from roles
                        // Common mappings: analyst -> analytics, engineer -> operations
                        for (String role : writerContext.getRoles()) {
                            String purpose = derivePurposeFromRole(role);
                            if (purpose != null) {
                                secLo |= SecurityDimensionsRegistry.getPurposeBit(purpose);
                            }
                        }
                        break;

                    // Add more dimensions as needed
                }
            }
        }

        return new BitmapDerivation.SecurityBitmap(secLo, secHi);
    }

    /**
     * Derive purpose from user role.
     *
     * This is a simple heuristic mapping. In production, this would likely
     * come from a configuration or OPA policy.
     */
    private String derivePurposeFromRole(String role) {
        String roleLower = role.toLowerCase();

        if (roleLower.contains("analyst")) {
            return "analytics";
        } else if (roleLower.contains("engineer") || roleLower.contains("developer")) {
            return "operations";
        } else if (roleLower.contains("marketing")) {
            return "marketing";
        } else if (roleLower.contains("support")) {
            return "support";
        }

        // Default: no purpose derivation
        return null;
    }

    /**
     * Validate that a bitmap meets minimum/maximum classification requirements.
     *
     * @param bitmap Security bitmap to validate
     * @throws WriteValidationException if validation fails
     */
    public void validateBitmap(BitmapDerivation.SecurityBitmap bitmap)
            throws WriteValidationException {

        // Decode bitmap to check sensitivity level
        Map<String, java.util.List<String>> dimensions =
                SecurityDimensionsRegistry.decode(bitmap.secLo, bitmap.secHi);

        java.util.List<String> sensitivityDims = dimensions.get("sensitivity");
        String actualSensitivity = sensitivityDims.isEmpty() ? null : sensitivityDims.get(0);

        for (Map.Entry<String, WriteRequirements> entry : writeRequirements.entrySet()) {
            String columnName = entry.getKey();
            WriteRequirements req = entry.getValue();

            // Check minimum sensitivity
            if (req.getMinSensitivity() != null && actualSensitivity != null) {
                int actualLevel = SecurityDimensionsRegistry.getSensitivityLevel(actualSensitivity);
                int minLevel = SecurityDimensionsRegistry.getSensitivityLevel(req.getMinSensitivity());

                if (actualLevel < minLevel) {
                    throw new WriteValidationException(
                            "Column '" + columnName + "' requires minimum sensitivity '"
                                    + req.getMinSensitivity() + "', got '" + actualSensitivity + "'"
                    );
                }
            }

            // Check maximum sensitivity
            if (req.getMaxSensitivity() != null && actualSensitivity != null) {
                int actualLevel = SecurityDimensionsRegistry.getSensitivityLevel(actualSensitivity);
                int maxLevel = SecurityDimensionsRegistry.getSensitivityLevel(req.getMaxSensitivity());

                if (actualLevel > maxLevel) {
                    throw new WriteValidationException(
                            "Column '" + columnName + "' has maximum sensitivity '"
                                    + req.getMaxSensitivity() + "', got '" + actualSensitivity + "'"
                    );
                }
            }
        }
    }

    /**
     * Write a record (delegates to underlying writer).
     *
     * Note: This does NOT automatically add _sec_lo/_sec_hi columns.
     * Use deriveBitmap() to get the bitmap and add it to your record
     * before calling this method.
     *
     * @param record Record to write
     * @throws IOException if write fails
     */
    public void write(T record) throws IOException {
        try {
            delegate.write(record);
            rowsWritten++;

            // Audit successful write (if handler is not no-op)
            auditHandler.onWriteEvent(new WriteAuditEventImpl(
                    writerContext.getUserId(),
                    filePath,
                    null,
                    "write_allowed",
                    "Row written successfully",
                    System.currentTimeMillis()
            ));

        } catch (Exception e) {
            // Audit the failure
            auditHandler.onWriteEvent(new WriteAuditEventImpl(
                    writerContext.getUserId(),
                    filePath,
                    null,
                    "write_failed",
                    "Write failed: " + e.getMessage(),
                    System.currentTimeMillis()
            ));
            throw e;
        }
    }

    /**
     * Get the number of rows written.
     */
    public long getRowsWritten() {
        return rowsWritten;
    }

    @Override
    public void close() throws IOException {
        try {
            delegate.close();
        } finally {
            auditHandler.close();
        }
    }
}
