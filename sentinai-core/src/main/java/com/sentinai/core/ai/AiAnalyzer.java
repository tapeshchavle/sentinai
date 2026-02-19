package com.sentinai.core.ai;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ThreatVerdict;

import java.util.List;

/**
 * Abstraction for AI-powered threat analysis.
 * Implementations wrap Spring AI's ChatClient for different providers.
 */
public interface AiAnalyzer {

    /**
     * Analyze a batch of request events for suspicious patterns.
     * This is called asynchronously — it can take seconds.
     *
     * @param events  Recent request events to analyze
     * @param context Additional context (e.g., "These are all failed logins")
     * @return List of verdicts for any detected threats
     */
    List<ThreatVerdict> analyze(List<RequestEvent> events, String context);

    /**
     * Analyze a single request with a specific question.
     *
     * @param event    The request to analyze
     * @param question Specific question (e.g., "Is this SQL injection?")
     * @return The AI's verdict
     */
    ThreatVerdict analyzeSingle(RequestEvent event, String question);

    /**
     * Check if the AI analyzer is available (API key configured, service
     * reachable).
     */
    boolean isAvailable();
}
