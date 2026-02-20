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
    private static final int DEFAULT_PER_FINGERPRINT_THRESHOLD = 10;
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
        List<ThreatVerdict> verdicts = new java.util.ArrayList<>();

        log.info("[SentinAI] [credential-guard] Analyzing batch of {} events", events.size());

        // Process each login failure
        for (RequestEvent event : events) {
            if (isLoginAttempt(event) && isLoginFailure(event.getResponseStatus())) {
                String fingerprint = computeFingerprint(event);
                String fpKey = "cg:fp:" + fingerprint;

                // Increment counter for this specific fingerprint
                long currentCount = context.getDecisionStore().incrementCounter(fpKey, DEFAULT_WINDOW);
                log.info("[SentinAI] [credential-guard] Login failure for FP {}: count is now {}/{}",
                        fingerprint, currentCount, getPerFingerprintThreshold(context));

                if (currentCount >= getPerFingerprintThreshold(context)) {
                    log.warn(
                            "[SentinAI] [credential-guard] Credential stuffing detected for fingerprint '{}': {} attempts",
                            fingerprint, currentCount);
                    verdicts.add(ThreatVerdict.block(ID,
                            "Credential stuffing: " + currentCount + " failed attempts",
                            fpKey,
                            DEFAULT_BLOCK_DURATION.toSeconds()));
                }

                // Increment counter for the target username
                String username = extractUsername(event);
                if (username != null && !username.isEmpty()) {
                    String userKey = "cg:user:" + username;
                    long userCount = context.getDecisionStore().incrementCounter(userKey, DEFAULT_WINDOW);
                    log.info("[SentinAI] [credential-guard] Login failure for Username {}: count is now {}/{}",
                            username, userCount, getPerUsernameThreshold(context));

                    if (userCount >= getPerUsernameThreshold(context)) {
                        log.warn(
                                "[SentinAI] [credential-guard] Brute force detected for username '{}': {} attempts",
                                username, userCount);
                        verdicts.add(ThreatVerdict.block(ID,
                                "Brute force attack: " + userCount + " failed attempts on user",
                                userKey,
                                DEFAULT_BLOCK_DURATION.toSeconds()));
                    }
                }
            } else {
                log.debug("[SentinAI] [credential-guard] Ignored event: Login Attempt={}, Status={}, Real Status={}",
                        isLoginAttempt(event), isLoginFailure(event.getResponseStatus()), event.getResponseStatus());
            }
        }

        long globalFailures = context.getDecisionStore().getCounter("cg:global:failures");
        log.info("[SentinAI] [credential-guard] Global failures: {}/{}", globalFailures,
                getGlobalSpikeThreshold(context));

        if (globalFailures > getGlobalSpikeThreshold(context)) {
            log.warn("[SentinAI] [credential-guard] Global login failure spike detected: {} failures",
                    globalFailures);
            verdicts.add(ThreatVerdict.suspicious(ID,
                    "Global login failure spike: " + globalFailures + " failures in window",
                    "global"));
        }

        return verdicts;
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

    private String extractUsername(RequestEvent event) {
        // Simple extraction for the sake of the demo
        if (event.getBody() != null && event.getBody().contains("\"username\"")) {
            try {
                // VERY basic JSON parsing just to grab the username value from the payload
                String[] parts = event.getBody().split("\"username\"");
                if (parts.length > 1) {
                    String afterUsername = parts[1];
                    int colonIdx = afterUsername.indexOf(':');
                    if (colonIdx != -1) {
                        String valuePart = afterUsername.substring(colonIdx + 1).trim();
                        if (valuePart.startsWith("\"")) {
                            int endQuoteIdx = valuePart.indexOf('"', 1);
                            if (endQuoteIdx != -1) {
                                return valuePart.substring(1, endQuoteIdx);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // ignore parsing errors
            }
        }
        return null;
    }

    private int getPerUsernameThreshold(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("per-username-failures");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_PER_USERNAME_THRESHOLD;
    }

    private int getPerFingerprintThreshold(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("per-fingerprint-failures");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_PER_FINGERPRINT_THRESHOLD;
    }

    private int getGlobalSpikeThreshold(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("global-failure-spike");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_GLOBAL_SPIKE_THRESHOLD;
    }
}
