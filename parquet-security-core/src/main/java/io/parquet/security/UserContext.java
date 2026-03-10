package io.parquet.security;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * User identity and attributes.
 * Engine-agnostic representation passed to security policy providers.
 */
public class UserContext {
    private final String userId;
    private final List<String> roles;
    private final String jurisdiction;
    private final Map<String, String> attributes;

    public UserContext(
        String userId,
        List<String> roles,
        String jurisdiction,
        Map<String, String> attributes
    ) {
        this.userId = Objects.requireNonNull(userId, "userId cannot be null");
        this.roles = roles != null ? Collections.unmodifiableList(roles) : Collections.emptyList();
        this.jurisdiction = jurisdiction;
        this.attributes = attributes != null ? Collections.unmodifiableMap(attributes) : Collections.emptyMap();
    }

    public String getUserId() {
        return userId;
    }

    public List<String> getRoles() {
        return roles;
    }

    public String getJurisdiction() {
        return jurisdiction;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserContext that = (UserContext) o;
        return Objects.equals(userId, that.userId) &&
               Objects.equals(roles, that.roles) &&
               Objects.equals(jurisdiction, that.jurisdiction) &&
               Objects.equals(attributes, that.attributes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, roles, jurisdiction, attributes);
    }

    @Override
    public String toString() {
        return "UserContext{" +
               "userId='" + userId + '\'' +
               ", roles=" + roles +
               ", jurisdiction='" + jurisdiction + '\'' +
               ", attributes=" + attributes +
               '}';
    }
}
