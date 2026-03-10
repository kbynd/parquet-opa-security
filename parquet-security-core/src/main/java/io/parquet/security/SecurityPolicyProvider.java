package io.parquet.security;

/**
 * Pluggable interface for security policy evaluation.
 *
 * Implementations can use various policy engines:
 * - OPA (Open Policy Agent)
 * - Azure AD
 * - AWS IAM
 * - Custom policy engines
 * - Hardcoded rules (for testing)
 *
 * The provider is called once per file read to get the permitted bitmap mask.
 */
public interface SecurityPolicyProvider {

    /**
     * Get permitted bitmap mask for a user.
     *
     * This method is called once per file read (on the driver/coordinator).
     * The returned mask is used to filter rows during scan.
     *
     * @param user User context (identity, roles, attributes)
     * @return Bitmap mask of permitted security dimensions
     * @throws SecurityException if policy evaluation fails and fail_open=false
     */
    PermittedMask getPermittedMask(UserContext user) throws SecurityException;

    /**
     * Version-aware policy lookup.
     *
     * Allows policy provider to handle schema evolution by returning
     * different masks for different schema versions.
     *
     * @param user User context
     * @param schemaVersion Schema version from row data (bits 60-63 of _sec_lo)
     * @return Bitmap mask for this schema version
     * @throws SecurityException if policy evaluation fails and fail_open=false
     */
    default PermittedMask getPermittedMask(UserContext user, int schemaVersion) throws SecurityException {
        // Default implementation ignores schema version
        return getPermittedMask(user);
    }
}
