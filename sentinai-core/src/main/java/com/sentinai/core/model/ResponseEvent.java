package com.sentinai.core.model;

/**
 * Wraps an API response body for outbound scanning (Data Leak Prevention).
 */
public class ResponseEvent {

    private final String requestId;
    private final String path;
    private final int statusCode;
    private final String contentType;
    private final String body;
    private final long responseTimeMs;

    public ResponseEvent(String requestId, String path, int statusCode,
            String contentType, String body, long responseTimeMs) {
        this.requestId = requestId;
        this.path = path;
        this.statusCode = statusCode;
        this.contentType = contentType;
        this.body = body;
        this.responseTimeMs = responseTimeMs;
    }

    public String getRequestId() {
        return requestId;
    }

    public String getPath() {
        return path;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getContentType() {
        return contentType;
    }

    public String getBody() {
        return body;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    /**
     * Returns a new ResponseEvent with a modified (redacted) body.
     */
    public ResponseEvent withBody(String newBody) {
        return new ResponseEvent(requestId, path, statusCode, contentType, newBody, responseTimeMs);
    }

    @Override
    public String toString() {
        return "ResponseEvent{path='" + path + "', status=" + statusCode + '}';
    }
}
