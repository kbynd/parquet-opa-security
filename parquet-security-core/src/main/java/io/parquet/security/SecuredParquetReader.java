package io.parquet.security;

import org.apache.parquet.example.data.Group;
import org.apache.parquet.hadoop.ParquetReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Secured Parquet reader that applies bitmap-based row filtering.
 *
 * This reader wraps a standard Parquet reader and filters rows based on
 * security bitmaps (_sec_lo, _sec_hi columns) and a permitted mask.
 *
 * Architecture:
 * - Engine-agnostic: No dependencies on Spark, DuckDB, Trino, etc.
 * - Pure filtering: Just applies bitmap logic, no policy evaluation
 * - Caller responsible for: Getting permitted mask from policy provider
 *
 * Usage:
 * <pre>
 * // 1. Caller gets permitted mask (calls OPA/policy provider)
 * SecurityPolicyProvider provider = new OpaSecurityPolicyProvider(...);
 * UserContext user = new UserContext(...);
 * PermittedMask mask = provider.getPermittedMask(user);
 *
 * // 2. Create standard Parquet reader
 * ParquetReader&lt;Group&gt; baseReader = ParquetReader.builder(...)
 *     .withConf(conf)
 *     .build();
 *
 * // 3. Wrap with secured reader (just filtering, no OPA call)
 * SecuredParquetReader&lt;Group&gt; reader = new SecuredParquetReader&lt;&gt;(
 *     baseReader,
 *     mask,
 *     new GroupSecurityColumnExtractor()
 * );
 *
 * // 4. Read filtered records
 * Group record;
 * while ((record = reader.read()) != null) {
 *     // Only permitted records returned
 * }
 * </pre>
 *
 * @param <T> Record type (Group, GenericRecord, etc.)
 */
public class SecuredParquetReader<T> implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(SecuredParquetReader.class);

    private final ParquetReader<T> delegate;
    private final PermittedMask permittedMask;
    private final SecurityColumnExtractor<T> columnExtractor;

    private long totalRecords = 0;
    private long filteredRecords = 0;

    /**
     * Create a secured Parquet reader.
     *
     * This constructor does NOT call any policy provider - the caller must
     * have already fetched the permitted mask.
     *
     * @param delegate Standard Parquet reader to wrap
     * @param permittedMask Bitmap mask of permitted dimensions (already computed by caller)
     * @param columnExtractor Extractor for security columns from records
     */
    public SecuredParquetReader(
        ParquetReader<T> delegate,
        PermittedMask permittedMask,
        SecurityColumnExtractor<T> columnExtractor
    ) {
        this.delegate = delegate;
        this.permittedMask = permittedMask;
        this.columnExtractor = columnExtractor;

        logger.debug("Security filter initialized: permitted_lo=0x{}, permitted_hi=0x{}",
            Long.toHexString(permittedMask.permittedLo),
            Long.toHexString(permittedMask.permittedHi)
        );
    }

    /**
     * Read next permitted record.
     *
     * Reads records from delegate until finding one that passes security filter,
     * or until EOF.
     *
     * @return Next permitted record, or null if EOF
     * @throws IOException on read error
     */
    public T read() throws IOException {
        while (true) {
            T record = delegate.read();

            if (record == null) {
                // EOF reached
                if (totalRecords > 0) {
                    logger.debug("Security filtering complete: total={}, filtered={}, passed={}",
                        totalRecords, filteredRecords, totalRecords - filteredRecords);
                }
                return null;
            }

            totalRecords++;

            // Check if file has security columns
            if (!columnExtractor.hasSecurityColumns(record)) {
                // Unsecured file - pass through all records
                logger.trace("Unsecured record (no _sec_lo column) - allowing");
                return record;
            }

            // Extract security bitmap
            long secLo = columnExtractor.extractSecLo(record);
            long secHi = columnExtractor.extractSecHi(record);

            // Check permission
            if (permittedMask.isPermitted(secLo, secHi)) {
                logger.trace("Record permitted: sec_lo=0x{}", Long.toHexString(secLo));
                return record;
            } else {
                logger.trace("Record filtered: sec_lo=0x{}", Long.toHexString(secLo));
                filteredRecords++;
                // Continue to next record
            }
        }
    }

    /**
     * Get filtering statistics.
     *
     * @return Statistics about how many records were filtered
     */
    public FilteringStats getStats() {
        return new FilteringStats(totalRecords, filteredRecords);
    }

    @Override
    public void close() throws IOException {
        delegate.close();

        if (totalRecords > 0) {
            logger.info("Security filtering stats: total={}, filtered={}, passed={}",
                totalRecords, filteredRecords, totalRecords - filteredRecords);
        }
    }

    /**
     * Statistics about security filtering.
     */
    public static class FilteringStats {
        public final long totalRecords;
        public final long filteredRecords;
        public final long passedRecords;

        public FilteringStats(long totalRecords, long filteredRecords) {
            this.totalRecords = totalRecords;
            this.filteredRecords = filteredRecords;
            this.passedRecords = totalRecords - filteredRecords;
        }

        @Override
        public String toString() {
            return String.format("FilteringStats{total=%d, filtered=%d, passed=%d}",
                totalRecords, filteredRecords, passedRecords);
        }
    }
}
