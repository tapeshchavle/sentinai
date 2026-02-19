package com.sentinai.core.ai;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ThreatLevel;
import com.sentinai.core.model.ThreatVerdict;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Default AI analyzer implementation using Spring AI's ChatClient.
 * Works with any OpenAI-compatible provider (Kimi, Nvidia NIM, OpenAI, Ollama).
 */
public class SpringAiAnalyzer implements AiAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(SpringAiAnalyzer.class);

    private final Object chatClient; // Spring AI ChatClient (Object to avoid hard dependency)
    private final boolean available;

    public SpringAiAnalyzer(Object chatClient) {
        this.chatClient = chatClient;
        this.available = chatClient != null;
        if (available) {
            log.info("[SentinAI] AI Analyzer initialized with Spring AI ChatClient");
        } else {
            log.warn("[SentinAI] AI Analyzer not available — no ChatClient configured. " +
                    "Modules will fall back to rule-based analysis.");
        }
    }

    @Override
    public List<ThreatVerdict> analyze(List<RequestEvent> events, String context) {
        if (!available || events.isEmpty()) {
            return List.of();
        }

        try {
            String prompt = buildBatchPrompt(events, context);
            String response = callAi(prompt);
            return parseResponse(response, context);
        } catch (Exception e) {
            log.error("[SentinAI] AI analysis failed: {}", e.getMessage());
            return List.of();
        }
    }

    @Override
    public ThreatVerdict analyzeSingle(RequestEvent event, String question) {
        if (!available) {
            return ThreatVerdict.safe("ai-analyzer");
        }

        try {
            String prompt = buildSinglePrompt(event, question);
            String response = callAi(prompt);
            return parseSingleResponse(response);
        } catch (Exception e) {
            log.error("[SentinAI] AI single analysis failed: {}", e.getMessage());
            return ThreatVerdict.safe("ai-analyzer");
        }
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    private String buildBatchPrompt(List<RequestEvent> events, String context) {
        StringBuilder sb = new StringBuilder();
        sb.append("You are SentinAI, an API security analyzer. Analyze the following batch of HTTP requests.\n\n");
        sb.append("Context: ").append(context).append("\n\n");
        sb.append("Events:\n");

        for (int i = 0; i < events.size(); i++) {
            RequestEvent e = events.get(i);
            sb.append(String.format("[%d] %s %s from IP=%s user=%s UA=%s status=%d time=%dms\n",
                    i + 1, e.getMethod(), e.getPath(), e.getSourceIp(),
                    e.getUserId() != null ? e.getUserId() : "anonymous",
                    e.getUserAgent() != null ? e.getUserAgent() : "unknown",
                    e.getResponseStatus(), e.getResponseTimeMs()));
        }

        sb.append("\nRespond with one of: SAFE, SUSPICIOUS, BLOCK\n");
        sb.append("If SUSPICIOUS or BLOCK, explain the pattern you detected.\n");
        sb.append("Format: VERDICT|REASON|TARGET_IDENTIFIER\n");
        return sb.toString();
    }

    private String buildSinglePrompt(RequestEvent event, String question) {
        return String.format(
                "You are SentinAI, an API security analyzer.\n\n" +
                        "Request: %s %s\nIP: %s\nUser: %s\nUser-Agent: %s\n" +
                        "Query: %s\nBody: %s\n\n" +
                        "Question: %s\n\n" +
                        "Respond with: SAFE, SUSPICIOUS, or BLOCK followed by a brief reason.\n" +
                        "Format: VERDICT|REASON",
                event.getMethod(), event.getPath(), event.getSourceIp(),
                event.getUserId(), event.getUserAgent(),
                event.getQueryString(), event.getBody(),
                question);
    }

    private String callAi(String prompt) {
        // Uses reflection to avoid compile-time dependency on Spring AI
        try {
            var clientClass = chatClient.getClass();
            var promptMethod = clientClass.getMethod("prompt", String.class);
            var callObj = promptMethod.invoke(chatClient, prompt);
            var callMethod = callObj.getClass().getMethod("call");
            var responseObj = callMethod.invoke(callObj);
            var contentMethod = responseObj.getClass().getMethod("content");
            return (String) contentMethod.invoke(responseObj);
        } catch (Exception e) {
            log.error("[SentinAI] Failed to call AI: {}", e.getMessage());
            throw new RuntimeException("AI call failed", e);
        }
    }

    private List<ThreatVerdict> parseResponse(String response, String context) {
        // Parse AI response lines in format: VERDICT|REASON|TARGET
        return response.lines()
                .filter(line -> line.contains("|"))
                .map(line -> {
                    String[] parts = line.split("\\|", 3);
                    String verdict = parts[0].trim().toUpperCase();
                    String reason = parts.length > 1 ? parts[1].trim() : "AI detected threat";
                    String target = parts.length > 2 ? parts[2].trim() : "unknown";

                    return switch (verdict) {
                        case "BLOCK" -> ThreatVerdict.block("ai-analyzer", reason, target, 1800);
                        case "SUSPICIOUS" -> ThreatVerdict.suspicious("ai-analyzer", reason, target);
                        default -> null;
                    };
                })
                .filter(v -> v != null)
                .collect(Collectors.toList());
    }

    private ThreatVerdict parseSingleResponse(String response) {
        String[] parts = response.split("\\|", 2);
        String verdict = parts[0].trim().toUpperCase();
        String reason = parts.length > 1 ? parts[1].trim() : "AI analysis";

        return switch (verdict) {
            case "BLOCK" -> ThreatVerdict.block("ai-analyzer", reason, "request", 1800);
            case "SUSPICIOUS" -> ThreatVerdict.suspicious("ai-analyzer", reason, "request");
            default -> ThreatVerdict.safe("ai-analyzer");
        };
    }
}
