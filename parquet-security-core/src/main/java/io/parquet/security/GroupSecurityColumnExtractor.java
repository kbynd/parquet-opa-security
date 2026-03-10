package io.parquet.security;

import org.apache.parquet.example.data.Group;
import org.apache.parquet.schema.GroupType;

/**
 * SecurityColumnExtractor implementation for Parquet Group records.
 *
 * Group is the standard record type when reading Parquet files with the simple API.
 */
public class GroupSecurityColumnExtractor implements SecurityColumnExtractor<Group> {

    private static final String SEC_LO_COLUMN = "_sec_lo";
    private static final String SEC_HI_COLUMN = "_sec_hi";

    @Override
    public boolean hasSecurityColumns(Group record) {
        GroupType schema = record.getType();
        return schema.containsField(SEC_LO_COLUMN);
    }

    @Override
    public long extractSecLo(Group record) {
        GroupType schema = record.getType();

        if (!schema.containsField(SEC_LO_COLUMN)) {
            throw new IllegalStateException("Record missing _sec_lo column");
        }

        int fieldIndex = schema.getFieldIndex(SEC_LO_COLUMN);
        return record.getLong(fieldIndex, 0);
    }

    @Override
    public long extractSecHi(Group record) {
        GroupType schema = record.getType();

        if (!schema.containsField(SEC_HI_COLUMN)) {
            return 0L; // _sec_hi optional, default to 0
        }

        int fieldIndex = schema.getFieldIndex(SEC_HI_COLUMN);
        return record.getLong(fieldIndex, 0);
    }
}
