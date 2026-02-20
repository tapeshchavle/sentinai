package com.sentinai.autoconfigure;

import com.sentinai.core.SentinAIEngine;
import com.sentinai.core.config.SentinAIProperties;
import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ResponseEvent;
import com.sentinai.core.model.ThreatVerdict;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Hooks SentinAI right into the Spring Security filter chain.
 * We're very careful here not to crash the host app — all errors are safely
 * caught and logged.
 */
public class SentinAISecurityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SentinAISecurityFilter.class);

    private final SentinAIEngine engine;
    private final SentinAIProperties properties;

    public SentinAISecurityFilter(SentinAIEngine engine, SentinAIProperties properties) {
        this.engine = engine;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!properties.isEnabled()) {
            filterChain.doFilter(request, response);
            return;
        }

        String requestId = UUID.randomUUID().toString().substring(0, 8);

        try {
            RequestEvent event = buildRequestEvent(request, requestId);
            ThreatVerdict verdict = engine.processRequest(event);

            if (verdict.shouldBlock() && properties.isActiveMode()) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter().write(String.format(
                        "{\"error\":\"Request blocked by SentinAI\",\"reason\":\"%s\",\"requestId\":\"%s\"}",
                        verdict.getReason(), requestId));
                return;
            }
        } catch (Exception e) {
            log.error("[SentinAI] Inbound analysis error (request not blocked): {}", e.getMessage());
        }

        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);

        try {
            filterChain.doFilter(request, wrappedResponse);
        } catch (Exception e) {
            // Forward any exceptions from the controller, but make sure to flush our
            // response buffer first
            wrappedResponse.copyBodyToResponse();
            throw e;
        }

        try {
            byte[] content = wrappedResponse.getContentAsByteArray();
            if (content.length > 0 && isJsonResponse(wrappedResponse)) {
                String responseBody = new String(content, wrappedResponse.getCharacterEncoding());
                ResponseEvent responseEvent = new ResponseEvent(
                        requestId, request.getRequestURI(),
                        wrappedResponse.getStatus(),
                        wrappedResponse.getContentType(),
                        responseBody,
                        0);

                ResponseEvent processedResponse = engine.processResponse(responseEvent);

                if (!processedResponse.getBody().equals(responseBody)) {
                    wrappedResponse.resetBuffer();
                    wrappedResponse.getWriter().write(processedResponse.getBody());
                }
            }
        } catch (Exception e) {
            log.error("[SentinAI] Outbound analysis error: {}", e.getMessage());
        }

        wrappedResponse.copyBodyToResponse();
    }

    private RequestEvent buildRequestEvent(HttpServletRequest request, String requestId) {
        Map<String, String> headers = new HashMap<>();
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            while (headerNames.hasMoreElements()) {
                String name = headerNames.nextElement();
                headers.put(name.toLowerCase(), request.getHeader(name));
            }
        }

        String userId = null;
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
                userId = auth.getName();
            }
        } catch (Exception e) {
            // Could not extract security context, they are likely not logged in
        }

        String sourceIp = request.getHeader("X-Forwarded-For");
        if (sourceIp == null || sourceIp.isEmpty()) {
            sourceIp = request.getHeader("X-Real-IP");
        }
        if (sourceIp == null || sourceIp.isEmpty()) {
            sourceIp = request.getRemoteAddr();
        }
        if (sourceIp != null && sourceIp.contains(",")) {
            sourceIp = sourceIp.split(",")[0].trim();
        }

        return RequestEvent.builder()
                .requestId(requestId)
                .method(request.getMethod())
                .path(request.getRequestURI())
                .queryString(request.getQueryString())
                .headers(headers)
                .sourceIp(sourceIp)
                .userAgent(request.getHeader("User-Agent"))
                .userId(userId)
                .sessionId(request.getSession(false) != null ? request.getSession().getId() : null)
                .build();
    }

    private boolean isJsonResponse(ContentCachingResponseWrapper response) {
        String contentType = response.getContentType();
        return contentType != null && contentType.contains("application/json");
    }
}
