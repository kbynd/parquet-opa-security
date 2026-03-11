package io.parquet.security.writer;

/**
 * Exception thrown when a row fails validation during write.
 *
 * This exception is thrown when:
 * - Bitmap doesn't meet minimum sensitivity requirements
 * - Bitmap exceeds maximum sensitivity requirements
 * - Required regulatory scopes are missing
 * - Other validation constraints are violated
 */
public class WriteValidationException extends Exception {

    private final String columnName;

    public WriteValidationException(String message) {
        super(message);
        this.columnName = null;
    }

    public WriteValidationException(String message, String columnName) {
        super(message);
        this.columnName = columnName;
    }

    public WriteValidationException(String message, Throwable cause) {
        super(message, cause);
        this.columnName = null;
    }

    public String getColumnName() {
        return columnName;
    }
}
