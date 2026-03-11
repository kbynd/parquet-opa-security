package io.parquet.security.writer;

/**
 * Exception thrown when a write operation is denied due to insufficient permissions.
 *
 * This exception is thrown when:
 * - Writer lacks required regulatory clearances
 * - Writer lacks required roles
 * - Write-up rule is violated (Bell-LaPadula)
 * - Minimum/maximum classification constraints are violated
 */
public class WriteAccessDeniedException extends Exception {

    private final String columnName;
    private final String userId;

    public WriteAccessDeniedException(String message) {
        super(message);
        this.columnName = null;
        this.userId = null;
    }

    public WriteAccessDeniedException(String message, String columnName, String userId) {
        super(message);
        this.columnName = columnName;
        this.userId = userId;
    }

    public WriteAccessDeniedException(String message, Throwable cause) {
        super(message, cause);
        this.columnName = null;
        this.userId = null;
    }

    public String getColumnName() {
        return columnName;
    }

    public String getUserId() {
        return userId;
    }
}
