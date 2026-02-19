package com.sentinai.module.credentialguard;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ResponseEvent;
import com.sentinai.core.model.ThreatVerdict;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.SecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Credential Guard Module — Detects slow-burn credential stuffing and
 * brute-force attacks.
 *
 * <p>
 * Detection strategy:
 * </p>
 * <ul>
 * <li>Tracks failed login attempts per TARGET USERNAME (not per IP)</li>
 * <li>Tracks failed logins per client FINGERPRINT (User-Agent + headers
 * hash)</li>
 * <li>Monitors global failure rate spikes</li>
 * <li>Sends suspicious patterns to AI for batch analysis</li>
 * </ul>
 */
@Component
public class CredentialGuardModule implements SecurityModule {

    private static final Logger log = LoggerFactory.getLogger(CredentialGuardModule.class);

    private static final String ID = "credential-guard";
    private static final Duration DEFAULT_WINDOW = Duration.ofMinutes(5);
    private static final int DEFAULT_PER_USERNAME_THRESHOLD = 10;
    private static final int DEFAULT_PER_FINGERPRINT_THRESHOLD = 20;
    private static final int DEFAULT_GLOBAL_SPIKE_THRESHOLD = 500;
    private static final Duration DEFAULT_BLOCK_DURATION = Duration.ofMinutes(30);

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getName() {
        return "Credential Guard";
    }

    @Override
    public int getOrder() {
        return 100;
    }

    @Override
    public ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext context) {
        // Only analyze POST requests to login-like endpoints
        if (!isLoginAttempt(event)) {
            return ThreatVerdict.safe(ID);
        }

        // Check if the source IP or fingerprint is already blocked
        String fingerprint = computeFingerprint(event);
        if (context.getDecisionStore().isBlocked("cg:fp:" + fingerprint)) {
            return ThreatVerdict.block(ID,
                    "Fingerprint blocked due to credential stuffing",
                    event.getSourceIp(), DEFAULT_BLOCK_DURATION.toSeconds());
        }

        return ThreatVerdict.safe(ID);
    }

    @Override
    public ResponseEvent analyzeResponse(ResponseEvent response, ModuleContext context) {
        // After the login response, check if it was a failure
        if (!isLoginPath(response.getPath())) {
            return response;
        }

        if (isLoginFailure(response.getStatusCode())) {
            recordFailure(response, context);
        }

        return response;
    }

    @Override
    public List<ThreatVerdict> analyzeBatch(List<RequestEvent> events, ModuleContext context) {
        // Filter to only login failures
        List<RequestEvent> loginFailures = events.stream()
                .filter(this::isLoginAttempt)
                .filter(e -> isLoginFailure(e.getResponseStatus()))
                .collect(Collectors.toList());

        if (loginFailures.isEmpty()) {
            return List.of();
        }

        // --- Check 1: Global failure spike ---
        long globalFailures = context.getDecisionStore()
                .getCounter("cg:global:failures");
        if (globalFailures > getGlobalSpikeThreshold(context)) {
            log.warn("[SentinAI] [credential-guard] Global login failure spike detected: {} failures",
                    globalFailures);
            // Don't block — alert. Could be a system issue.
            return List.of(ThreatVerdict.suspicious(ID,
                    "Global login failure spike: " + globalFailures + " failures in window",
                    "global"));
        }

        // --- Check 2: Per-username analysis ---
        // Group failures by target username (extracted from path or body)
        Map<String, Long> failuresByTarget = loginFailures.stream()
                .filter(e -> e.getPath() != null)
                .collect(Collectors.groupingBy(
                        e -> e.getUserId() != null ? e.getUserId() : e.getSourceIp(),
                        Collectors.counting()));

        return failuresByTarget.entrySet().stream()
                .filter(entry -> entry.getValue() >= getPerUsernameThreshold(context))
                .map(entry -> {
                    log.warn("[SentinAI] [credential-guard] Credential stuffing detected on target '{}': {} attempts",
                            entry.getKey(), entry.getValue());
                    return ThreatVerdict.block(ID,
                            "Credential stuffing: " + entry.getValue() + " failed attempts on target",
                            entry.getKey(),
                            DEFAULT_BLOCK_DURATION.toSeconds());
                })
                .collect(Collectors.toList());
    }

    // --- Private helpers ---

    private void recordFailure(ResponseEvent response, ModuleContext context) {
        // Increment per-path failure counter
        String pathKey = "cg:path:" + response.getPath();
        long count = context.getDecisionStore().incrementCounter(pathKey, DEFAULT_WINDOW);

        // Increment global failure counter
        context.getDecisionStore().incrementCounter("cg:global:failures", DEFAULT_WINDOW);

        if (count % 5 == 0) {
            log.debug("[SentinAI] [credential-guard] {} failures on {} in current window",
                    count, response.getPath());
        }
    }

    private boolean isLoginAttempt(RequestEvent event) {
        return "POST".equalsIgnoreCase(event.getMethod()) && isLoginPath(event.getPath());
    }

    private boolean isLoginPath(String path) {
        if (path == null)
            return false;
        String lower = path.toLowerCase();
        return lower.contains("/login") || lower.contains("/auth") ||
                lower.contains("/signin") || lower.contains("/token") ||
                lower.contains("/authenticate");
    }

    private boolean isLoginFailure(int statusCode) {
        return statusCode == 401 || statusCode == 403 || statusCode == 400;
    }

    private String computeFingerprint(RequestEvent event) {
        // Combine User-Agent + Accept-Language + other headers for fingerprinting
        String ua = event.getUserAgent() != null ? event.getUserAgent() : "";
        String acceptLang = event.getHeaders().getOrDefault("accept-language", "");
        String accept = event.getHeaders().getOrDefault("accept", "");
        return Integer.toHexString((ua + "|" + acceptLang + "|" + accept).hashCode());
    }

    private int getPerUsernameThreshold(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("per-username-failures");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_PER_USERNAME_THRESHOLD;
    }

    private int getGlobalSpikeThreshold(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("global-failure-spike");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_GLOBAL_SPIKE_THRESHOLD;
    }
}
