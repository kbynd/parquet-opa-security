package io.parquet.security;

import org.apache.parquet.example.data.Group;
import org.apache.parquet.example.data.simple.SimpleGroup;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.PrimitiveType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.*;
import static org.apache.parquet.schema.Type.Repetition.REQUIRED;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for GroupSecurityColumnExtractor.
 */
class GroupSecurityColumnExtractorTest {

    private GroupSecurityColumnExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new GroupSecurityColumnExtractor();
    }

    @Test
    void testHasSecurityColumns_WithSecLo() {
        // Schema with _sec_lo column
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name"),
            new PrimitiveType(REQUIRED, INT64, "_sec_lo")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");
        record.append("_sec_lo", 123L);

        assertTrue(extractor.hasSecurityColumns(record));
    }

    @Test
    void testHasSecurityColumns_WithoutSecLo() {
        // Schema without _sec_lo column
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name"),
            new PrimitiveType(REQUIRED, INT32, "age")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");
        record.append("age", 30);

        assertFalse(extractor.hasSecurityColumns(record));
    }

    @Test
    void testExtractSecLo_Success() {
        // Schema with _sec_lo
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name"),
            new PrimitiveType(REQUIRED, INT64, "_sec_lo")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");
        record.append("_sec_lo", 0x103L);

        long secLo = extractor.extractSecLo(record);

        assertEquals(0x103L, secLo);
    }

    @Test
    void testExtractSecLo_MissingColumn() {
        // Schema without _sec_lo
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");

        // Should throw IllegalStateException
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> {
            extractor.extractSecLo(record);
        });

        assertTrue(ex.getMessage().contains("_sec_lo"));
    }

    @Test
    void testExtractSecHi_Success() {
        // Schema with _sec_hi
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name"),
            new PrimitiveType(REQUIRED, INT64, "_sec_lo"),
            new PrimitiveType(REQUIRED, INT64, "_sec_hi")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");
        record.append("_sec_lo", 0x103L);
        record.append("_sec_hi", 0x456L);

        long secHi = extractor.extractSecHi(record);

        assertEquals(0x456L, secHi);
    }

    @Test
    void testExtractSecHi_MissingColumn() {
        // Schema without _sec_hi (optional column)
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name"),
            new PrimitiveType(REQUIRED, INT64, "_sec_lo")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");
        record.append("_sec_lo", 0x103L);

        // Should return 0 when _sec_hi is missing
        long secHi = extractor.extractSecHi(record);

        assertEquals(0L, secHi);
    }

    @Test
    void testExtractSecLo_LargeValue() {
        // Test with large bitmap value
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, INT64, "_sec_lo")
        );

        Group record = new SimpleGroup(schema);
        record.append("_sec_lo", 0x7FFF_FFFF_FFFF_FFFFL);

        long secLo = extractor.extractSecLo(record);

        assertEquals(0x7FFF_FFFF_FFFF_FFFFL, secLo);
    }

    @Test
    void testExtractSecHi_LargeValue() {
        // Test with large bitmap value
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, INT64, "_sec_lo"),
            new PrimitiveType(REQUIRED, INT64, "_sec_hi")
        );

        Group record = new SimpleGroup(schema);
        record.append("_sec_lo", 0L);
        record.append("_sec_hi", 0x7FFF_FFFF_FFFF_FFFFL);

        long secHi = extractor.extractSecHi(record);

        assertEquals(0x7FFF_FFFF_FFFF_FFFFL, secHi);
    }

    @Test
    void testExtractSecLo_WithMultipleColumns() {
        // Schema with security columns among other columns
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, BINARY, "name"),
            new PrimitiveType(REQUIRED, INT32, "age"),
            new PrimitiveType(REQUIRED, BINARY, "email"),
            new PrimitiveType(REQUIRED, INT64, "_sec_lo"),
            new PrimitiveType(REQUIRED, INT64, "_sec_hi"),
            new PrimitiveType(REQUIRED, BINARY, "department")
        );

        Group record = new SimpleGroup(schema);
        record.append("name", "Alice");
        record.append("age", 30);
        record.append("email", "alice@example.com");
        record.append("_sec_lo", 0xABCDL);
        record.append("_sec_hi", 0x1234L);
        record.append("department", "Engineering");

        assertEquals(0xABCDL, extractor.extractSecLo(record));
        assertEquals(0x1234L, extractor.extractSecHi(record));
        assertTrue(extractor.hasSecurityColumns(record));
    }

    @Test
    void testExtractSecLo_ZeroValue() {
        // Test with zero bitmap (no security dimensions)
        MessageType schema = new MessageType("test",
            new PrimitiveType(REQUIRED, INT64, "_sec_lo")
        );

        Group record = new SimpleGroup(schema);
        record.append("_sec_lo", 0L);

        long secLo = extractor.extractSecLo(record);

        assertEquals(0L, secLo);
    }
}
