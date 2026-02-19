package com.sentinai.core.plugin;

import com.sentinai.core.ai.AiAnalyzer;
import com.sentinai.core.config.SentinAIProperties;
import com.sentinai.core.store.DecisionStore;

/**
 * Shared context passed to each SecurityModule during analysis.
 * Provides access to the decision store, AI analyzer, and configuration.
 */
public class ModuleContext {

    private final DecisionStore decisionStore;
    private final AiAnalyzer aiAnalyzer;
    private final SentinAIProperties properties;

    public ModuleContext(DecisionStore decisionStore, AiAnalyzer aiAnalyzer,
            SentinAIProperties properties) {
        this.decisionStore = decisionStore;
        this.aiAnalyzer = aiAnalyzer;
        this.properties = properties;
    }

    /** Access to Redis/InMemory blacklists, rate counters, etc. */
    public DecisionStore getDecisionStore() {
        return decisionStore;
    }

    /** Access to the AI model for async analysis. */
    public AiAnalyzer getAiAnalyzer() {
        return aiAnalyzer;
    }

    /** Access to configuration properties. */
    public SentinAIProperties getProperties() {
        return properties;
    }
}
