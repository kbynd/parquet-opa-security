package io.parquet.security.audit;

import java.util.Map;

/**
 * Represents a write audit event for security tracking.
 *
 * Events are created when:
 * - A write is allowed
 * - A write is denied due to insufficient clearances
 * - A write fails validation (e.g., minimum sensitivity not met)
 *
 * Implementations can send these events to:
 * - Log files
 * - SIEM systems (Splunk, ELK, etc.)
 * - Metrics systems (Prometheus, Micrometer)
 * - Custom audit trails
 */
public interface WriteAuditEvent {

    /**
     * User ID of the writer attempting the operation.
     */
    String getUserId();

    /**
     * Path to the Parquet file being written.
     */
    String getFilePath();

    /**
     * Name of the column involved (if applicable).
     * May be null for file-level operations.
     */
    String getColumnName();

    /**
     * Action type:
     * - "write_allowed": Write succeeded
     * - "write_denied": Write denied due to access control
     * - "validation_failed": Write failed due to validation error
     * - "schema_access_denied": User lacks permission to write to schema
     */
    String getAction();

    /**
     * Reason for the action (especially useful for denials).
     * Examples:
     * - "Row written successfully"
     * - "User lacks PII clearance"
     * - "Column requires minimum sensitivity 'confidential'"
     */
    String getReason();

    /**
     * Timestamp of the event (milliseconds since epoch).
     */
    long getTimestamp();

    /**
     * Additional metadata about the event.
     * May include:
     * - User roles
     * - Required clearances
     * - Actual vs required sensitivity levels
     * - etc.
     */
    Map<String, String> getMetadata();
}
