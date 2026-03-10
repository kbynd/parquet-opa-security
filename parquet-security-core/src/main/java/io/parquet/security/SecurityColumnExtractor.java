package io.parquet.security;

/**
 * Interface for extracting security columns from Parquet records.
 *
 * Different record types (Group, GenericRecord, etc.) need different extraction logic.
 * Implementations of this interface handle the specifics of each record type.
 *
 * @param <T> Record type
 */
public interface SecurityColumnExtractor<T> {

    /**
     * Check if record has security columns (_sec_lo, _sec_hi).
     *
     * @param record Parquet record
     * @return true if record has security columns, false otherwise
     */
    boolean hasSecurityColumns(T record);

    /**
     * Extract _sec_lo value from record.
     *
     * @param record Parquet record
     * @return _sec_lo value (64-bit bitmap)
     * @throws IllegalStateException if _sec_lo column not found
     */
    long extractSecLo(T record);

    /**
     * Extract _sec_hi value from record.
     *
     * @param record Parquet record
     * @return _sec_hi value (64-bit bitmap), or 0 if column not present
     */
    long extractSecHi(T record);
}
