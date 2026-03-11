package io.parquet.security.audit;

/**
 * Handler for write audit events.
 *
 * Implementations can:
 * - Log to files
 * - Send to SIEM systems (Splunk, ELK, etc.)
 * - Record metrics (Prometheus, Micrometer)
 * - Send to custom audit trails
 *
 * The default implementation (NoOpAuditHandler) has zero overhead and is
 * optimized away by the JIT compiler.
 *
 * Thread-safety: Implementations must be thread-safe if used in multi-threaded
 * environments (e.g., Spark executors).
 */
public interface WriteAuditHandler {

    /**
     * Handle a write audit event.
     *
     * This method is called for every write operation, including:
     * - Successful writes
     * - Denied writes (access control failure)
     * - Validation failures
     *
     * Implementations should be fast and non-blocking. If the audit handler
     * needs to perform I/O, consider using async logging or queuing.
     *
     * @param event The audit event to handle
     */
    void onWriteEvent(WriteAuditEvent event);

    /**
     * Called when the writer is closed.
     *
     * Implementations can use this to flush buffers, close connections, etc.
     * The default implementation does nothing.
     */
    default void close() {
        // No-op by default
    }
}
