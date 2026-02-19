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
 * Query Shield Module — Protects against application-layer DDoS via expensive
 * queries.
 *
 * <p>
 * Three layers of defense:
 * </p>
 * <ol>
 * <li>Pattern Check: Instantly blocks known-dangerous payloads (SQL wildcards,
 * injections)</li>
 * <li>Concurrency Limiter: Limits simultaneous requests per endpoint</li>
 * <li>Circuit Breaker: Temporarily stops forwarding if endpoint latency
 * spikes</li>
 * </ol>
 */
@Component
public class QueryShieldModule implements SecurityModule {

    private static final Logger log = LoggerFactory.getLogger(QueryShieldModule.class);
    private static final String ID = "query-shield";

    // Known dangerous patterns — instant block
    private static final List<Pattern> DANGEROUS_PATTERNS = List.of(
            Pattern.compile("(?i)['\"]\\s*(OR|AND)\\s+['\"]?\\d"), // SQL injection: ' OR '1
            Pattern.compile("(?i)\\bSLEEP\\s*\\("), // SQL time-based injection
            Pattern.compile("(?i)\\bUNION\\s+SELECT\\b"), // SQL UNION injection
            Pattern.compile("(?i)\\$where\\b"), // NoSQL injection
            Pattern.compile("(?i)\\bDROP\\s+TABLE\\b"), // SQL DDL injection
            Pattern.compile("(?i)<script[^>]*>"), // XSS
            Pattern.compile("(?i)javascript\\s*:"), // XSS via protocol
            Pattern.compile("(?i)\\beval\\s*\\(") // Code injection
    );

    // Wildcard abuse patterns — flag for analysis
    private static final List<Pattern> WILDCARD_PATTERNS = List.of(
            Pattern.compile("^%+$"), // Pure wildcard: %
            Pattern.compile("^_+$"), // Pure underscore wildcard: ___
            Pattern.compile("(?i)\\bLIKE\\s+'%") // LIKE '%...'
    );

    // Concurrency tracking per endpoint
    private final Map<String, AtomicInteger> activeConcurrency = new ConcurrentHashMap<>();
    private static final int DEFAULT_MAX_CONCURRENCY = 50;

    // Circuit breaker state
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

        // --- Layer 1: Pattern Check (instant) ---
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

        // Check wildcard abuse
        String queryParam = event.getQueryString();
        if (queryParam != null) {
            for (Pattern p : WILDCARD_PATTERNS) {
                // Check each query parameter value
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

        // --- Layer 2: Circuit Breaker Check ---
        CircuitState circuit = circuitStates.get(event.getPath());
        if (circuit != null && circuit.isOpen()) {
            return ThreatVerdict.throttle(ID,
                    "Circuit breaker OPEN for " + event.getPath() + " — endpoint under stress",
                    event.getSourceIp());
        }

        // --- Layer 3: Concurrency Limiter ---
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
        // Decrement concurrency counter
        AtomicInteger active = activeConcurrency.get(response.getPath());
        if (active != null) {
            active.decrementAndGet();
        }

        // Track response time for circuit breaker
        if (response.getResponseTimeMs() > 3000) { // > 3 seconds = slow
            CircuitState circuit = circuitStates.computeIfAbsent(
                    response.getPath(), k -> new CircuitState());
            circuit.recordFailure();

            if (circuit.shouldOpen()) {
                circuit.open();
                log.warn("[SentinAI] [query-shield] Circuit OPENED for {} — {} consecutive slow responses",
                        response.getPath(), circuit.failureCount);
            }
        } else {
            // Successful fast response — reset circuit
            CircuitState circuit = circuitStates.get(response.getPath());
            if (circuit != null) {
                circuit.recordSuccess();
            }
        }

        return response;
    }

    private String buildFullQuery(RequestEvent event) {
        StringBuilder sb = new StringBuilder();
        if (event.getQueryString() != null)
            sb.append(event.getQueryString());
        if (event.getBody() != null)
            sb.append(" ").append(event.getBody());
        return sb.toString();
    }

    // --- Circuit Breaker State ---
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
            // Auto-close after recovery timeout (half-open)
            if (System.currentTimeMillis() - openedAt > RECOVERY_MS) {
                open = false;
                failureCount = 0;
                return false;
            }
            return true;
        }
    }
}
