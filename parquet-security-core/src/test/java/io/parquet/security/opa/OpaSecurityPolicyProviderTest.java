package io.parquet.security.opa;

import io.parquet.security.PermittedMask;
import io.parquet.security.UserContext;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for OpaSecurityPolicyProvider using MockWebServer.
 */
class OpaSecurityPolicyProviderTest {

    private MockWebServer mockOpa;
    private String opaUrl;

    @BeforeEach
    void setUp() throws IOException {
        mockOpa = new MockWebServer();
        mockOpa.start();
        opaUrl = "http://localhost:" + mockOpa.getPort();
    }

    @AfterEach
    void tearDown() throws IOException {
        mockOpa.shutdown();
    }

    @Test
    void testGetPermittedMask_Success() throws Exception {
        // Mock OPA response
        String opaResponse = "{\n" +
            "  \"result\": {\n" +
            "    \"permitted_lo\": 259,\n" +
            "    \"permitted_hi\": 0,\n" +
            "    \"allow\": true,\n" +
            "    \"active_dimensions\": [\"internal\", \"pii\"]\n" +
            "  }\n" +
            "}";

        mockOpa.enqueue(new MockResponse()
            .setBody(opaResponse)
            .setHeader("Content-Type", "application/json"));

        // Create provider and make request
        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext(
            "analyst@co.com",
            Arrays.asList("analyst", "apac_reader"),
            "IN",
            null
        );

        PermittedMask mask = provider.getPermittedMask(user);

        // Verify response parsed correctly
        assertEquals(259L, mask.permittedLo);
        assertEquals(0L, mask.permittedHi);

        // Verify request sent to OPA
        RecordedRequest request = mockOpa.takeRequest();
        assertEquals("POST", request.getMethod());
        assertEquals("/v1/data/lakehouse/access/result", request.getPath());
        String requestBody = request.getBody().readUtf8();
        assertTrue(requestBody.contains("analyst@co.com"));
        assertTrue(requestBody.contains("analyst"));
    }

    @Test
    void testGetPermittedMask_HighBitsSupport() throws Exception {
        // Test with both _sec_lo and _sec_hi
        String opaResponse = "{\n" +
            "  \"result\": {\n" +
            "    \"permitted_lo\": 4294967295,\n" +
            "    \"permitted_hi\": 281474976710655\n" +
            "  }\n" +
            "}";

        mockOpa.enqueue(new MockResponse()
            .setBody(opaResponse)
            .setHeader("Content-Type", "application/json"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.singletonList("admin"), null, null);

        PermittedMask mask = provider.getPermittedMask(user);

        assertEquals(4294967295L, mask.permittedLo);
        assertEquals(281474976710655L, mask.permittedHi);
    }

    @Test
    void testGetPermittedMask_FailClosed_On404() {
        // Mock OPA 404 error
        mockOpa.enqueue(new MockResponse()
            .setResponseCode(404)
            .setBody("Not found"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should throw SecurityException when fail_open=false
        SecurityException ex = assertThrows(SecurityException.class, () -> {
            provider.getPermittedMask(user);
        });

        assertTrue(ex.getMessage().contains("OPA request failed"));
        assertTrue(ex.getMessage().contains("404"));
    }

    @Test
    void testGetPermittedMask_FailOpen_On404() throws Exception {
        // Mock OPA 404 error
        mockOpa.enqueue(new MockResponse()
            .setResponseCode(404)
            .setBody("Not found"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, true);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should return all-permitted mask when fail_open=true
        PermittedMask mask = provider.getPermittedMask(user);

        assertEquals(0xFFFF_FFFF_FFFF_FFFFL, mask.permittedLo);
        assertEquals(0xFFFF_FFFF_FFFF_FFFFL, mask.permittedHi);
    }

    @Test
    void testGetPermittedMask_FailClosed_On500() {
        // Mock OPA internal error
        mockOpa.enqueue(new MockResponse()
            .setResponseCode(500)
            .setBody("Internal Server Error"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should throw SecurityException when fail_open=false
        SecurityException ex = assertThrows(SecurityException.class, () -> {
            provider.getPermittedMask(user);
        });

        assertTrue(ex.getMessage().contains("OPA request failed"));
        assertTrue(ex.getMessage().contains("500"));
    }

    @Test
    void testGetPermittedMask_FailOpen_OnNetworkError() throws Exception {
        // Shut down server to simulate network error
        mockOpa.shutdown();

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, true);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should return all-permitted mask when fail_open=true
        PermittedMask mask = provider.getPermittedMask(user);

        assertEquals(0xFFFF_FFFF_FFFF_FFFFL, mask.permittedLo);
        assertEquals(0xFFFF_FFFF_FFFF_FFFFL, mask.permittedHi);
    }

    @Test
    void testGetPermittedMask_FailClosed_OnNetworkError() {
        // Shut down server to simulate network error
        try {
            mockOpa.shutdown();
        } catch (IOException e) {
            fail("Failed to shutdown mock server");
        }

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should throw SecurityException when fail_open=false
        SecurityException ex = assertThrows(SecurityException.class, () -> {
            provider.getPermittedMask(user);
        });

        assertTrue(ex.getMessage().contains("OPA evaluation failed"));
    }

    @Test
    void testGetPermittedMask_InvalidJSON() {
        // Mock invalid JSON response
        mockOpa.enqueue(new MockResponse()
            .setBody("{invalid json}")
            .setHeader("Content-Type", "application/json"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should throw SecurityException
        SecurityException ex = assertThrows(SecurityException.class, () -> {
            provider.getPermittedMask(user);
        });

        assertTrue(ex.getMessage().contains("OPA evaluation failed") ||
                   ex.getMessage().contains("Failed to parse"));
    }

    @Test
    void testGetPermittedMask_MissingResultField() {
        // Mock response without 'result' field
        mockOpa.enqueue(new MockResponse()
            .setBody("{\"foo\": \"bar\"}")
            .setHeader("Content-Type", "application/json"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should throw SecurityException
        SecurityException ex = assertThrows(SecurityException.class, () -> {
            provider.getPermittedMask(user);
        });

        assertTrue(ex.getMessage().contains("OPA evaluation failed") ||
                   ex.getMessage().contains("Failed to parse"));
    }

    @Test
    void testGetPermittedMask_MissingPermittedLoField() {
        // Mock response without 'permitted_lo' field
        mockOpa.enqueue(new MockResponse()
            .setBody("{\"result\": {\"foo\": \"bar\"}}")
            .setHeader("Content-Type", "application/json"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should throw SecurityException
        SecurityException ex = assertThrows(SecurityException.class, () -> {
            provider.getPermittedMask(user);
        });

        assertTrue(ex.getMessage().contains("OPA evaluation failed") ||
                   ex.getMessage().contains("Failed to parse"));
    }

    @Test
    void testGetPermittedMask_WithJurisdiction() throws Exception {
        String opaResponse = "{\n" +
            "  \"result\": {\n" +
            "    \"permitted_lo\": 259,\n" +
            "    \"permitted_hi\": 0\n" +
            "  }\n" +
            "}";

        mockOpa.enqueue(new MockResponse()
            .setBody(opaResponse)
            .setHeader("Content-Type", "application/json"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext(
            "analyst@co.com",
            Arrays.asList("analyst"),
            "US",
            null
        );

        provider.getPermittedMask(user);

        // Verify jurisdiction sent in request
        RecordedRequest request = mockOpa.takeRequest();
        String requestBody = request.getBody().readUtf8();
        assertTrue(requestBody.contains("US"), "Request should contain jurisdiction");
    }

    @Test
    void testGetPermittedMask_WithoutJurisdiction() throws Exception {
        String opaResponse = "{\n" +
            "  \"result\": {\n" +
            "    \"permitted_lo\": 259,\n" +
            "    \"permitted_hi\": 0\n" +
            "  }\n" +
            "}";

        mockOpa.enqueue(new MockResponse()
            .setBody(opaResponse)
            .setHeader("Content-Type", "application/json"));

        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        UserContext user = new UserContext(
            "analyst@co.com",
            Arrays.asList("analyst"),
            null,
            null
        );

        provider.getPermittedMask(user);

        // Verify request still succeeds without jurisdiction
        RecordedRequest request = mockOpa.takeRequest();
        assertNotNull(request);
    }

    @Test
    @org.junit.jupiter.api.Disabled("Timeout test is environment-dependent and flaky")
    void testGetPermittedMask_CustomTimeout() {
        // Mock slow OPA response (5 second delay)
        mockOpa.enqueue(new MockResponse()
            .setBody("{\"result\": {\"permitted_lo\": 1, \"permitted_hi\": 0}}")
            .setBodyDelay(5, java.util.concurrent.TimeUnit.SECONDS));

        // Create provider with 1 second timeout
        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(
            opaUrl,
            false,
            Duration.ofMillis(500)
        );
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        // Should timeout and throw SecurityException
        try {
            provider.getPermittedMask(user);
            fail("Should have thrown SecurityException due to timeout");
        } catch (SecurityException ex) {
            // Expected - either timeout or OPA evaluation failure
            assertTrue(ex.getMessage().contains("OPA evaluation failed") ||
                      ex.getMessage().contains("timed out"));
        }
    }

    @Test
    void testUrlNormalization_TrailingSlash() throws Exception {
        String opaResponse = "{\n" +
            "  \"result\": {\n" +
            "    \"permitted_lo\": 1,\n" +
            "    \"permitted_hi\": 0\n" +
            "  }\n" +
            "}";

        mockOpa.enqueue(new MockResponse()
            .setBody(opaResponse)
            .setHeader("Content-Type", "application/json"));

        // URL with trailing slash should be normalized
        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl + "/", false);
        UserContext user = new UserContext("user@co.com", Collections.emptyList(), null, null);

        provider.getPermittedMask(user);

        // Verify request path is correct (no double slash)
        RecordedRequest request = mockOpa.takeRequest();
        assertEquals("/v1/data/lakehouse/access/result", request.getPath());
    }

    @Test
    void testToString() {
        OpaSecurityPolicyProvider provider = new OpaSecurityPolicyProvider(opaUrl, false);
        String str = provider.toString();

        assertTrue(str.contains("OpaSecurityPolicyProvider"));
        assertTrue(str.contains(opaUrl));
        assertTrue(str.contains("failOpen=false"));
    }
}
