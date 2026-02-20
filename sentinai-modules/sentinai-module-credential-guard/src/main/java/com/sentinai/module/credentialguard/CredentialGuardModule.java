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
 * Detects brute force login attempts and credential stuffing.
 * Returns a 403 response if the login target or the client fingerprint attempts
 * too many failed logins within a rolling time window.
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
        // We only care about POST requests pushing credentials to a login route
        if (!isLoginAttempt(event)) {
            return ThreatVerdict.safe(ID);
        }

        // Does this client fingerprint have a history of stuffing?
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
        // Only check the response status for login routes
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
        // We only care about login failures here
        List<RequestEvent> loginFailures = events.stream()
                .filter(this::isLoginAttempt)
                .filter(e -> isLoginFailure(e.getResponseStatus()))
                .collect(Collectors.toList());

        if (loginFailures.isEmpty()) {
            return List.of();
        }

        long globalFailures = context.getDecisionStore()
                .getCounter("cg:global:failures");
        if (globalFailures > getGlobalSpikeThreshold(context)) {
            log.warn("[SentinAI] [credential-guard] Global login failure spike detected: {} failures",
                    globalFailures);
            // Big spike in global login failures. Don't block the IP (might be a system
            // issue), just log it.
            return List.of(ThreatVerdict.suspicious(ID,
                    "Global login failure spike: " + globalFailures + " failures in window",
                    "global"));
        }

        // See if a specific target user has too many failed attempts
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
        // Hash a combination of the user agent and some headers to reliably identify
        // the client across IPs
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
