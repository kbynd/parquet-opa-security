package io.parquet.security.writer;

import io.parquet.security.UserContext;
import org.apache.parquet.schema.MessageType;
import org.apache.parquet.schema.Types;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.BINARY;
import static org.apache.parquet.schema.PrimitiveType.PrimitiveTypeName.INT64;
import static org.junit.jupiter.api.Assertions.*;

class WriteRequirementsTest {

    @Test
    void testParseWriteRequirements() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("email")
                .required(INT64).named("salary")
                .named("employees");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.email.security.write.min_clearance", "pii");
        fileMetadata.put("column.email.security.write.required_roles", "data_engineer,admin");
        fileMetadata.put("column.salary.security.min_sensitivity", "confidential");
        fileMetadata.put("column.salary.security.max_sensitivity", "restricted");
        fileMetadata.put("column.salary.security.enforce_write_up", "true");

        Map<String, WriteRequirements> requirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        // Email column requirements
        WriteRequirements emailReq = requirements.get("email");
        assertNotNull(emailReq);
        assertEquals("email", emailReq.getColumnName());
        assertEquals(Arrays.asList("pii"), emailReq.getRequiredRegulatoryScopes());
        assertEquals(Arrays.asList("data_engineer", "admin"), emailReq.getRequiredRoles());
        assertNull(emailReq.getMinSensitivity());
        assertNull(emailReq.getMaxSensitivity());
        assertFalse(emailReq.isEnforceWriteUp());
        assertFalse(emailReq.isAutoClassify());

        // Salary column requirements
        WriteRequirements salaryReq = requirements.get("salary");
        assertNotNull(salaryReq);
        assertEquals("salary", salaryReq.getColumnName());
        assertTrue(salaryReq.getRequiredRegulatoryScopes().isEmpty());
        assertTrue(salaryReq.getRequiredRoles().isEmpty());
        assertEquals("confidential", salaryReq.getMinSensitivity());
        assertEquals("restricted", salaryReq.getMaxSensitivity());
        assertTrue(salaryReq.isEnforceWriteUp());
        assertFalse(salaryReq.isAutoClassify());
    }

    @Test
    void testParseAutoClassifyRequirements() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("notes")
                .named("customers");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.notes.security.auto_classify", "true");
        fileMetadata.put("column.notes.security.inherit_from_writer", "geographic,purpose");

        Map<String, WriteRequirements> requirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        WriteRequirements notesReq = requirements.get("notes");
        assertNotNull(notesReq);
        assertTrue(notesReq.isAutoClassify());
        assertEquals(Arrays.asList("geographic", "purpose"), notesReq.getInheritFromWriter());
    }

    @Test
    void testEmptyMetadata() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("name")
                .named("customers");

        Map<String, String> fileMetadata = new HashMap<>();

        Map<String, WriteRequirements> requirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        assertTrue(requirements.isEmpty());
    }

    @Test
    void testValidateWriterWithRequiredRoles() {
        WriteRequirements requirements = new WriteRequirements(
                "email",
                Collections.emptyList(),
                Arrays.asList("data_engineer", "admin"),
                null,
                null,
                false,
                false,
                Collections.emptyList()
        );

        // User with data_engineer role - should succeed
        UserContext validWriter = new UserContext(
                "user@example.com",
                Arrays.asList("analyst", "data_engineer"),
                "US",
                Collections.emptyMap()
        );
        assertDoesNotThrow(() -> requirements.validateWriter(validWriter));

        // User without required role - should fail
        UserContext invalidWriter = new UserContext(
                "user@example.com",
                Arrays.asList("analyst", "viewer"),
                "US",
                Collections.emptyMap()
        );
        WriteAccessDeniedException exception = assertThrows(
                WriteAccessDeniedException.class,
                () -> requirements.validateWriter(invalidWriter)
        );
        assertTrue(exception.getMessage().contains("data_engineer"));
        assertTrue(exception.getMessage().contains("admin"));
    }

    @Test
    void testHasWriteRequirements() {
        // No requirements
        WriteRequirements noReqs = new WriteRequirements(
                "col1",
                Collections.emptyList(),
                Collections.emptyList(),
                null,
                null,
                false,
                false,
                Collections.emptyList()
        );
        assertFalse(noReqs.hasWriteRequirements());

        // Has required roles
        WriteRequirements withRoles = new WriteRequirements(
                "col2",
                Collections.emptyList(),
                Arrays.asList("admin"),
                null,
                null,
                false,
                false,
                Collections.emptyList()
        );
        assertTrue(withRoles.hasWriteRequirements());

        // Has min sensitivity
        WriteRequirements withMinSens = new WriteRequirements(
                "col3",
                Collections.emptyList(),
                Collections.emptyList(),
                "confidential",
                null,
                false,
                false,
                Collections.emptyList()
        );
        assertTrue(withMinSens.hasWriteRequirements());

        // Has auto-classify
        WriteRequirements withAutoClassify = new WriteRequirements(
                "col4",
                Collections.emptyList(),
                Collections.emptyList(),
                null,
                null,
                false,
                true,
                Arrays.asList("geographic")
        );
        assertTrue(withAutoClassify.hasWriteRequirements());
    }

    @Test
    void testParseCommaSeparatedValues() {
        MessageType schema = Types.buildMessage()
                .required(BINARY).named("data")
                .named("test");

        Map<String, String> fileMetadata = new HashMap<>();
        fileMetadata.put("column.data.security.write.min_clearance", "pii, phi, financial");
        fileMetadata.put("column.data.security.write.required_roles", "admin");

        Map<String, WriteRequirements> requirements =
                WriteRequirements.parseFromFileMetadata(schema, fileMetadata);

        WriteRequirements dataReq = requirements.get("data");
        assertNotNull(dataReq);
        assertEquals(Arrays.asList("pii", "phi", "financial"), dataReq.getRequiredRegulatoryScopes());
        assertEquals(Arrays.asList("admin"), dataReq.getRequiredRoles());
    }

    @Test
    void testToString() {
        WriteRequirements requirements = new WriteRequirements(
                "email",
                Arrays.asList("pii", "phi"),
                Arrays.asList("admin"),
                "confidential",
                "restricted",
                true,
                false,
                Collections.emptyList()
        );

        String str = requirements.toString();
        assertTrue(str.contains("email"));
        assertTrue(str.contains("pii"));
        assertTrue(str.contains("phi"));
        assertTrue(str.contains("admin"));
        assertTrue(str.contains("confidential"));
        assertTrue(str.contains("restricted"));
        assertTrue(str.contains("enforceWriteUp=true"));
    }
}
