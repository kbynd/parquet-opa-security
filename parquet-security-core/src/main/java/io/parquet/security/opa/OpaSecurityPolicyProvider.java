package io.parquet.security.opa;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import io.parquet.security.PermittedMask;
import io.parquet.security.SecurityPolicyProvider;
import io.parquet.security.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * OPA (Open Policy Agent) implementation of SecurityPolicyProvider.
 * Calls OPA REST API to evaluate security policy and get permitted bitmap mask.
 *
 * Still engine-agnostic - just makes HTTP calls to OPA.
 *
 * Example OPA policy path: /v1/data/lakehouse/access/result
 */
public class OpaSecurityPolicyProvider implements SecurityPolicyProvider {

    private static final Logger logger = LoggerFactory.getLogger(OpaSecurityPolicyProvider.class);
    private static final Gson gson = new Gson();

    private final String opaUrl;
    private final boolean failOpen;
    private final HttpClient httpClient;
    private final Duration timeout;

    /**
     * Create OPA policy provider.
     *
     * @param opaUrl Base URL of OPA server (e.g., "http://localhost:8181")
     * @param failOpen If true, allow access on OPA errors. If false, deny access.
     */
    public OpaSecurityPolicyProvider(String opaUrl, boolean failOpen) {
        this(opaUrl, failOpen, Duration.ofSeconds(5));
    }

    /**
     * Create OPA policy provider with custom timeout.
     *
     * @param opaUrl Base URL of OPA server
     * @param failOpen If true, allow access on OPA errors. If false, deny access.
     * @param timeout HTTP request timeout
     */
    public OpaSecurityPolicyProvider(String opaUrl, boolean failOpen, Duration timeout) {
        this.opaUrl = opaUrl.endsWith("/") ? opaUrl.substring(0, opaUrl.length() - 1) : opaUrl;
        this.failOpen = failOpen;
        this.timeout = timeout;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(timeout)
            .build();

        logger.info("Initialized OPA policy provider: url={}, failOpen={}", this.opaUrl, failOpen);
    }

    @Override
    public PermittedMask getPermittedMask(UserContext user) throws SecurityException {
        try {
            // Build OPA request
            String requestBody = buildOpaRequest(user);

            logger.debug("Calling OPA for user: {}", user.getUserId());

            // Make HTTP request to OPA
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(opaUrl + "/v1/data/lakehouse/access/result"))
                .header("Content-Type", "application/json")
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            // Handle response
            if (response.statusCode() != 200) {
                String errorMsg = String.format(
                    "OPA request failed: status=%d, body=%s",
                    response.statusCode(),
                    response.body()
                );
                logger.error(errorMsg);

                if (failOpen) {
                    logger.warn("Failing open: allowing all access");
                    return new PermittedMask(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL);
                } else {
                    throw new SecurityException(errorMsg);
                }
            }

            // Parse OPA response
            PermittedMask mask = parseOpaResponse(response.body());

            logger.debug("OPA response for user {}: permitted_lo=0x{}, permitted_hi=0x{}",
                user.getUserId(),
                Long.toHexString(mask.permittedLo),
                Long.toHexString(mask.permittedHi)
            );

            return mask;

        } catch (SecurityException e) {
            throw e; // Re-throw security exceptions
        } catch (Exception e) {
            logger.error("OPA evaluation failed", e);

            if (failOpen) {
                logger.warn("Failing open: allowing all access");
                return new PermittedMask(0xFFFF_FFFF_FFFF_FFFFL, 0xFFFF_FFFF_FFFF_FFFFL);
            } else {
                throw new SecurityException("OPA evaluation failed", e);
            }
        }
    }

    /**
     * Build OPA request JSON.
     *
     * Format:
     * {
     *   "input": {
     *     "user": {
     *       "id": "analyst@co.com",
     *       "roles": ["analyst", "apac_reader"],
     *       "jurisdiction": "IN"
     *     }
     *   }
     * }
     */
    private String buildOpaRequest(UserContext user) {
        JsonObject input = new JsonObject();
        JsonObject userObj = new JsonObject();

        userObj.addProperty("id", user.getUserId());
        userObj.add("roles", gson.toJsonTree(user.getRoles()));

        if (user.getJurisdiction() != null) {
            userObj.addProperty("jurisdiction", user.getJurisdiction());
        }

        // Add custom attributes if present
        if (!user.getAttributes().isEmpty()) {
            JsonObject attrs = new JsonObject();
            user.getAttributes().forEach(attrs::addProperty);
            userObj.add("attributes", attrs);
        }

        input.add("user", userObj);

        JsonObject root = new JsonObject();
        root.add("input", input);

        return gson.toJson(root);
    }

    /**
     * Parse OPA response JSON.
     *
     * Expected format:
     * {
     *   "result": {
     *     "permitted_lo": 12345,
     *     "permitted_hi": 0,
     *     "allow": true,
     *     "active_dimensions": ["internal", "pii", "region_apac"]
     *   }
     * }
     */
    private PermittedMask parseOpaResponse(String json) throws SecurityException {
        try {
            JsonObject root = gson.fromJson(json, JsonObject.class);

            if (!root.has("result")) {
                throw new SecurityException("OPA response missing 'result' field");
            }

            JsonObject result = root.getAsJsonObject("result");

            if (!result.has("permitted_lo")) {
                throw new SecurityException("OPA response missing 'permitted_lo' field");
            }

            long permittedLo = result.get("permitted_lo").getAsLong();
            long permittedHi = result.has("permitted_hi") ? result.get("permitted_hi").getAsLong() : 0L;

            return new PermittedMask(permittedLo, permittedHi);

        } catch (Exception e) {
            throw new SecurityException("Failed to parse OPA response: " + json, e);
        }
    }

    @Override
    public String toString() {
        return "OpaSecurityPolicyProvider{" +
               "opaUrl='" + opaUrl + '\'' +
               ", failOpen=" + failOpen +
               ", timeout=" + timeout +
               '}';
    }
}
