package com.sentinai.module.dlp;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ResponseEvent;
import com.sentinai.core.model.ThreatVerdict;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.SecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Data Leak Prevention Module — Scans outgoing API responses for sensitive
 * data.
 *
 * <p>
 * Detects and redacts:
 * </p>
 * <ul>
 * <li>Credit card numbers (Luhn validation)</li>
 * <li>SSN (US format)</li>
 * <li>Aadhaar numbers (India)</li>
 * <li>Password hashes (bcrypt, argon2, SHA-256)</li>
 * <li>API keys (OpenAI, AWS, GitHub, etc.)</li>
 * <li>JWT tokens</li>
 * <li>Private keys (PEM format)</li>
 * </ul>
 */
@Component
public class DataLeakPreventionModule implements SecurityModule {

    private static final Logger log = LoggerFactory.getLogger(DataLeakPreventionModule.class);
    private static final String ID = "data-leak-prevention";
    private static final String REDACTED = "[REDACTED BY SENTINAI]";

    /**
     * Auth endpoints where JWT tokens are intentionally returned.
     * DLP will NOT redact JWT tokens on these paths so frontends can use them.
     */
    private static final Set<String> AUTH_PATHS = Set.of(
            "/api/login", "/api/auth", "/api/token", "/api/register",
            "/api/refresh", "/api/oauth", "/login", "/auth", "/token",
            "/oauth/token", "/api/auth/login", "/api/auth/register");

    /**
     * Each detector has a name, regex pattern, and optional validator.
     */
    private static final List<SensitiveDataDetector> DETECTORS = List.of(
            // Credit Cards (13-19 digits, with optional separators)
            new SensitiveDataDetector("credit-card",
                    Pattern.compile(
                            "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\\b"),
                    DataLeakPreventionModule::luhnCheck),

            // SSN (US): XXX-XX-XXXX
            new SensitiveDataDetector("ssn",
                    Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b"), null),

            // Aadhaar (India): XXXX XXXX XXXX or XXXX-XXXX-XXXX
            new SensitiveDataDetector("aadhaar",
                    Pattern.compile("\\b\\d{4}[\\s-]\\d{4}[\\s-]\\d{4}\\b"), null),

            // Password hashes: bcrypt
            new SensitiveDataDetector("password-hash-bcrypt",
                    Pattern.compile("\\$2[aby]?\\$\\d{2}\\$[./A-Za-z0-9]{53}"), null),

            // Password hashes: argon2
            new SensitiveDataDetector("password-hash-argon2",
                    Pattern.compile("\\$argon2[id]{1,2}\\$[^\"\\s]+"), null),

            // API Keys: OpenAI
            new SensitiveDataDetector("api-key-openai",
                    Pattern.compile("sk-[A-Za-z0-9]{20,}"), null),

            // API Keys: AWS
            new SensitiveDataDetector("api-key-aws",
                    Pattern.compile("AKIA[0-9A-Z]{16}"), null),

            // API Keys: GitHub
            new SensitiveDataDetector("api-key-github",
                    Pattern.compile("gh[ps]_[A-Za-z0-9_]{36,}"), null),

            // JWT Tokens
            new SensitiveDataDetector("jwt-token",
                    Pattern.compile("eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]+"), null),

            // Private Keys (PEM)
            new SensitiveDataDetector("private-key",
                    Pattern.compile("-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), null),

            // Generic long hex strings (potential secrets/hashes)
            new SensitiveDataDetector("hex-secret",
                    Pattern.compile("(?<=\")[a-f0-9]{64}(?=\")"), null));

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getName() {
        return "Data Leak Prevention";
    }

    @Override
    public int getOrder() {
        return 800;
    } // Runs on response path, late in chain

    @Override
    public ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext context) {
        // DLP only analyzes responses, not requests
        return ThreatVerdict.safe(ID);
    }

    @Override
    public ResponseEvent analyzeResponse(ResponseEvent response, ModuleContext context) {
        // Skip non-JSON responses and empty bodies
        if (response.getBody() == null || response.getBody().isEmpty()) {
            return response;
        }
        if (response.getContentType() != null && !response.getContentType().contains("json")) {
            return response;
        }

        // Skip large responses for performance
        if (response.getBody().length() > 1_048_576) { // 1MB
            return response;
        }

        String body = response.getBody();
        List<Detection> detections = new ArrayList<>();

        // Run all detectors
        for (SensitiveDataDetector detector : DETECTORS) {
            // Skip JWT token detection on auth endpoints — tokens are intentional there
            if ("jwt-token".equals(detector.name) && isAuthPath(response.getPath())) {
                continue;
            }

            Matcher matcher = detector.pattern.matcher(body);
            while (matcher.find()) {
                String match = matcher.group();

                // Run optional validator (e.g., Luhn check for credit cards)
                if (detector.validator != null && !detector.validator.validate(match)) {
                    continue; // Failed validation — skip (false positive)
                }

                detections.add(new Detection(detector.name, match, matcher.start(), matcher.end()));
            }
        }

        if (detections.isEmpty()) {
            return response;
        }

        // Log all detections
        for (Detection d : detections) {
            log.warn("[SentinAI] [data-leak-prevention] Sensitive data detected in response to {}: " +
                    "type={}, value={}...{}",
                    response.getPath(), d.detectorName,
                    d.matchedValue.substring(0, Math.min(4, d.matchedValue.length())),
                    d.matchedValue.substring(Math.max(0, d.matchedValue.length() - 4)));
        }

        // Determine action based on mode
        boolean isActiveMode = context.getProperties().isActiveMode();
        String moduleMode = getModuleMode(context);

        if ("BLOCK".equalsIgnoreCase(moduleMode) && isActiveMode) {
            // Return empty body with error
            log.error("[SentinAI] [data-leak-prevention] BLOCKED response to {} — {} sensitive items found",
                    response.getPath(), detections.size());
            return response.withBody("{\"error\":\"Response blocked by SentinAI: contains sensitive data\"}");
        }

        if ("REDACT".equalsIgnoreCase(moduleMode) || isActiveMode) {
            // Redact all detected values
            String redactedBody = body;
            for (Detection d : detections) {
                redactedBody = redactedBody.replace(d.matchedValue, REDACTED);
            }

            log.info("[SentinAI] [data-leak-prevention] Redacted {} sensitive items in response to {}",
                    detections.size(), response.getPath());
            return response.withBody(redactedBody);
        }

        // LOG mode — just warn, don't modify
        return response;
    }

    // --- Luhn Algorithm (Credit Card Validation) ---
    private static boolean luhnCheck(String number) {
        String digits = number.replaceAll("[^0-9]", "");
        if (digits.length() < 13 || digits.length() > 19)
            return false;

        int sum = 0;
        boolean alternate = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int n = Character.getNumericValue(digits.charAt(i));
            if (alternate) {
                n *= 2;
                if (n > 9)
                    n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    /**
     * Check if the given path is an authentication endpoint where JWT tokens
     * should NOT be redacted (the frontend needs them).
     */
    private boolean isAuthPath(String path) {
        if (path == null)
            return false;
        // Exact match first
        if (AUTH_PATHS.contains(path))
            return true;
        // Check common auth path patterns
        String lower = path.toLowerCase();
        return lower.contains("/login") || lower.contains("/auth/")
                || lower.contains("/token") || lower.contains("/oauth");
    }

    private String getModuleMode(ModuleContext context) {
        var config = context.getProperties().getModuleConfig(ID);
        Object mode = config.get("mode");
        return mode != null ? mode.toString() : "LOG"; // Default to LOG for safety
    }

    // --- Internal classes ---

    @FunctionalInterface
    interface Validator {
        boolean validate(String value);
    }

    private record SensitiveDataDetector(String name, Pattern pattern, Validator validator) {
    }

    private record Detection(String detectorName, String matchedValue, int start, int end) {
    }
}
