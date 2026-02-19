package com.sentinai.core.model;

import java.time.Instant;
import java.util.Map;

/**
 * Captures metadata about an incoming HTTP request for security analysis.
 * This is the primary input to all SecurityModules.
 */
public class RequestEvent {

    private final String requestId;
    private final String method;
    private final String path;
    private final String queryString;
    private final Map<String, String> headers;
    private final String body;
    private final String sourceIp;
    private final String userAgent;
    private final String userId; // Extracted from JWT/Session (null if unauthenticated)
    private final String sessionId;
    private final String fingerprint; // JA3 or computed fingerprint
    private final Instant timestamp;
    private final int responseStatus; // 0 if not yet known (pre-filter)
    private final long responseTimeMs; // 0 if not yet known

    private RequestEvent(Builder builder) {
        this.requestId = builder.requestId;
        this.method = builder.method;
        this.path = builder.path;
        this.queryString = builder.queryString;
        this.headers = builder.headers != null ? Map.copyOf(builder.headers) : Map.of();
        this.body = builder.body;
        this.sourceIp = builder.sourceIp;
        this.userAgent = builder.userAgent;
        this.userId = builder.userId;
        this.sessionId = builder.sessionId;
        this.fingerprint = builder.fingerprint;
        this.timestamp = builder.timestamp != null ? builder.timestamp : Instant.now();
        this.responseStatus = builder.responseStatus;
        this.responseTimeMs = builder.responseTimeMs;
    }

    // Getters
    public String getRequestId() {
        return requestId;
    }

    public String getMethod() {
        return method;
    }

    public String getPath() {
        return path;
    }

    public String getQueryString() {
        return queryString;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getBody() {
        return body;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getUserId() {
        return userId;
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public int getResponseStatus() {
        return responseStatus;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    /**
     * Creates a copy of this event with response data populated (post-filter).
     */
    public RequestEvent withResponseData(int status, long responseTimeMs) {
        return new Builder()
                .requestId(this.requestId)
                .method(this.method)
                .path(this.path)
                .queryString(this.queryString)
                .headers(this.headers)
                .body(this.body)
                .sourceIp(this.sourceIp)
                .userAgent(this.userAgent)
                .userId(this.userId)
                .sessionId(this.sessionId)
                .fingerprint(this.fingerprint)
                .timestamp(this.timestamp)
                .responseStatus(status)
                .responseTimeMs(responseTimeMs)
                .build();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String requestId;
        private String method;
        private String path;
        private String queryString;
        private Map<String, String> headers;
        private String body;
        private String sourceIp;
        private String userAgent;
        private String userId;
        private String sessionId;
        private String fingerprint;
        private Instant timestamp;
        private int responseStatus;
        private long responseTimeMs;

        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder queryString(String queryString) {
            this.queryString = queryString;
            return this;
        }

        public Builder headers(Map<String, String> headers) {
            this.headers = headers;
            return this;
        }

        public Builder body(String body) {
            this.body = body;
            return this;
        }

        public Builder sourceIp(String sourceIp) {
            this.sourceIp = sourceIp;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public Builder userId(String userId) {
            this.userId = userId;
            return this;
        }

        public Builder sessionId(String sessionId) {
            this.sessionId = sessionId;
            return this;
        }

        public Builder fingerprint(String fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        public Builder timestamp(Instant timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder responseStatus(int responseStatus) {
            this.responseStatus = responseStatus;
            return this;
        }

        public Builder responseTimeMs(long responseTimeMs) {
            this.responseTimeMs = responseTimeMs;
            return this;
        }

        public RequestEvent build() {
            return new RequestEvent(this);
        }
    }

    @Override
    public String toString() {
        return "RequestEvent{" +
                "method='" + method + '\'' +
                ", path='" + path + '\'' +
                ", sourceIp='" + sourceIp + '\'' +
                ", userId='" + userId + '\'' +
                '}';
    }
}
