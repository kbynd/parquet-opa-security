package io.parquet.security.audit;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Default implementation of WriteAuditEvent.
 */
public class WriteAuditEventImpl implements WriteAuditEvent {

    private final String userId;
    private final String filePath;
    private final String columnName;
    private final String action;
    private final String reason;
    private final long timestamp;
    private final Map<String, String> metadata;

    public WriteAuditEventImpl(
            String userId,
            String filePath,
            String columnName,
            String action,
            String reason,
            long timestamp
    ) {
        this(userId, filePath, columnName, action, reason, timestamp, Collections.emptyMap());
    }

    public WriteAuditEventImpl(
            String userId,
            String filePath,
            String columnName,
            String action,
            String reason,
            long timestamp,
            Map<String, String> metadata
    ) {
        this.userId = userId;
        this.filePath = filePath;
        this.columnName = columnName;
        this.action = action;
        this.reason = reason;
        this.timestamp = timestamp;
        this.metadata = new HashMap<>(metadata);
    }

    @Override
    public String getUserId() {
        return userId;
    }

    @Override
    public String getFilePath() {
        return filePath;
    }

    @Override
    public String getColumnName() {
        return columnName;
    }

    @Override
    public String getAction() {
        return action;
    }

    @Override
    public String getReason() {
        return reason;
    }

    @Override
    public long getTimestamp() {
        return timestamp;
    }

    @Override
    public Map<String, String> getMetadata() {
        return Collections.unmodifiableMap(metadata);
    }

    @Override
    public String toString() {
        return "WriteAuditEvent{" +
                "action='" + action + '\'' +
                ", userId='" + userId + '\'' +
                ", filePath='" + filePath + '\'' +
                ", columnName='" + columnName + '\'' +
                ", reason='" + reason + '\'' +
                ", timestamp=" + timestamp +
                ", metadata=" + metadata +
                '}';
    }
}
