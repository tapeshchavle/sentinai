package com.sentinai.module.queryshield;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ResponseEvent;
import com.sentinai.core.model.ThreatVerdict;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.SecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Blocks application-layer DDoS attacks caused by expensive queries.
 *
 * We do this in three ways:
 * 1. Instantly blocking known malicious payloads (like SQL injection or
 * wildcards)
 * 2. Capping the number of simultaneous requests for a single endpoint
 * 3. Tripping a circuit breaker if an endpoint starts responding too slowly
 */
@Component
public class QueryShieldModule implements SecurityModule {

    private static final Logger log = LoggerFactory.getLogger(QueryShieldModule.class);
    private static final String ID = "query-shield";

    // Block these immediately - they're definitely malicious
    private static final List<Pattern> DANGEROUS_PATTERNS = List.of(
            Pattern.compile("(?i)['\"]\\s*(OR|AND)\\s+['\"]?\\d"),
            Pattern.compile("(?i)\\bSLEEP\\s*\\("),
            Pattern.compile("(?i)\\bUNION\\s+SELECT\\b"),
            Pattern.compile("(?i)\\$where\\b"),
            Pattern.compile("(?i)\\bDROP\\s+TABLE\\b"),
            Pattern.compile("(?i)<script[^>]*>"),
            Pattern.compile("(?i)javascript\\s*:"),
            Pattern.compile("(?i)\\beval\\s*\\("));

    // Flag these for review - returning too much data can crash the DB
    private static final List<Pattern> WILDCARD_PATTERNS = List.of(
            Pattern.compile("^%+$"),
            Pattern.compile("^_+$"),
            Pattern.compile("(?i)\\bLIKE\\s+'%"));

    // Keep track of how many requests are hitting each endpoint right now
    private final Map<String, AtomicInteger> activeConcurrency = new ConcurrentHashMap<>();
    private static final int DEFAULT_MAX_CONCURRENCY = 50;

    // Keep track of endpoints that are failing/timing out
    private final Map<String, CircuitState> circuitStates = new ConcurrentHashMap<>();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getName() {
        return "Query Shield";
    }

    @Override
    public int getOrder() {
        return 200;
    }

    @Override
    public ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext context) {

        String fullQuery = buildFullQuery(event);

        for (Pattern p : DANGEROUS_PATTERNS) {
            if (p.matcher(fullQuery).find()) {
                log.warn("[SentinAI] [query-shield] Dangerous pattern detected: {} in {}",
                        p.pattern(), event.getPath());
                return ThreatVerdict.block(ID,
                        "Dangerous query pattern detected: " + p.pattern(),
                        event.getSourceIp(),
                        Duration.ofMinutes(10).toSeconds());
            }
        }

        // Check for wildcard abuse in the query params
        String queryParam = event.getQueryString();
        if (queryParam != null) {
            try {
                queryParam = java.net.URLDecoder.decode(queryParam, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) {
            }
            for (Pattern p : WILDCARD_PATTERNS) {
                for (String part : queryParam.split("&")) {
                    String[] kv = part.split("=", 2);
                    if (kv.length == 2 && p.matcher(kv[1]).find()) {
                        return ThreatVerdict.block(ID,
                                "Wildcard query abuse detected: " + kv[0] + "=" + kv[1],
                                event.getSourceIp(),
                                Duration.ofMinutes(5).toSeconds());
                    }
                }
            }
        }

        CircuitState circuit = circuitStates.get(event.getPath());
        if (circuit != null && circuit.isOpen()) {
            return ThreatVerdict.throttle(ID,
                    "Circuit breaker OPEN for " + event.getPath() + " — endpoint under stress",
                    event.getSourceIp());
        }

        AtomicInteger active = activeConcurrency.computeIfAbsent(
                event.getPath(), k -> new AtomicInteger(0));
        int currentActive = active.incrementAndGet();

        if (currentActive > DEFAULT_MAX_CONCURRENCY) {
            active.decrementAndGet();
            log.warn("[SentinAI] [query-shield] Concurrency limit reached for {}: {}/{}",
                    event.getPath(), currentActive, DEFAULT_MAX_CONCURRENCY);
            return ThreatVerdict.throttle(ID,
                    "Concurrency limit reached for " + event.getPath(),
                    event.getSourceIp());
        }

        return ThreatVerdict.safe(ID);
    }

    @Override
    public ResponseEvent analyzeResponse(ResponseEvent response, ModuleContext context) {
        // Let go of the concurrency lock once the response is done
        AtomicInteger active = activeConcurrency.get(response.getPath());
        if (active != null) {
            active.decrementAndGet();
        }

        // If the request took longer than 3 seconds, record it so we can trip the
        // breaker if needed
        if (response.getResponseTimeMs() > 3000) {
            CircuitState circuit = circuitStates.computeIfAbsent(
                    response.getPath(), k -> new CircuitState());
            circuit.recordFailure();

            if (circuit.shouldOpen()) {
                circuit.open();
                log.warn("[SentinAI] [query-shield] Circuit OPENED for {} — {} consecutive slow responses",
                        response.getPath(), circuit.failureCount);
            }
        } else {
            // Speed looks good here, resolve any ongoing circuit breaker issues
            CircuitState circuit = circuitStates.get(response.getPath());
            if (circuit != null) {
                circuit.recordSuccess();
            }
        }

        return response;
    }

    private String buildFullQuery(RequestEvent event) {
        StringBuilder sb = new StringBuilder();
        if (event.getQueryString() != null) {
            try {
                sb.append(java.net.URLDecoder.decode(event.getQueryString(), java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception e) {
                sb.append(event.getQueryString());
            }
        }
        if (event.getBody() != null)
            sb.append(" ").append(event.getBody());
        return sb.toString();
    }

    private static class CircuitState {
        int failureCount = 0;
        boolean open = false;
        long openedAt = 0;
        static final int FAILURE_THRESHOLD = 5;
        static final long RECOVERY_MS = 30_000; // 30 seconds

        void recordFailure() {
            failureCount++;
        }

        void recordSuccess() {
            failureCount = Math.max(0, failureCount - 1);
            if (failureCount == 0)
                open = false;
        }

        boolean shouldOpen() {
            return failureCount >= FAILURE_THRESHOLD;
        }

        void open() {
            this.open = true;
            this.openedAt = System.currentTimeMillis();
        }

        boolean isOpen() {
            if (!open)
                return false;
            // Give the endpoint another try after 30 seconds
            if (System.currentTimeMillis() - openedAt > RECOVERY_MS) {
                open = false;
                failureCount = 0;
                return false;
            }
            return true;
        }
    }
}
