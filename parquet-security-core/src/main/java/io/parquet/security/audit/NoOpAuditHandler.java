package io.parquet.security.audit;

/**
 * No-operation audit handler that does nothing.
 *
 * This is the default handler and has zero overhead - the JIT compiler
 * optimizes away the method calls entirely.
 *
 * Use this when you don't need auditing (most production scenarios).
 */
public class NoOpAuditHandler implements WriteAuditHandler {

    @Override
    public void onWriteEvent(WriteAuditEvent event) {
        // Intentionally empty - zero overhead
    }

    @Override
    public void close() {
        // Intentionally empty
    }
}
