package com.sentinai.core;

import com.sentinai.core.config.SentinAIProperties;
import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ResponseEvent;
import com.sentinai.core.model.ThreatVerdict;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.ModuleRegistry;
import com.sentinai.core.plugin.SecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;

/**
 * The central orchestrator for SentinAI.
 * Coordinates all SecurityModules in the correct order for request/response
 * analysis.
 */
public class SentinAIEngine {

    private static final Logger log = LoggerFactory.getLogger(SentinAIEngine.class);

    private final ModuleRegistry registry;
    private final ModuleContext context;
    private final SentinAIProperties properties;
    private final Executor asyncExecutor;

    // Buffer for collecting events for async batch analysis
    private final List<RequestEvent> eventBuffer = new CopyOnWriteArrayList<>();
    private static final int BATCH_SIZE = 20;

    public SentinAIEngine(ModuleRegistry registry, ModuleContext context,
            SentinAIProperties properties, Executor asyncExecutor) {
        this.registry = registry;
        this.context = context;
        this.properties = properties;
        this.asyncExecutor = asyncExecutor;
        log.info("[SentinAI] Engine started in {} mode", properties.getMode());
    }

    /**
     * Process an incoming request through all enabled inbound modules.
     * Called synchronously by the Security Filter — must be FAST.
     *
     * @return The first blocking verdict, or a SAFE verdict if all pass.
     */
    public ThreatVerdict processRequest(RequestEvent event) {
        if (!properties.isEnabled()) {
            return ThreatVerdict.safe("engine");
        }

        // Check if path is excluded
        if (isExcludedPath(event.getPath())) {
            return ThreatVerdict.safe("engine");
        }

        // Check blacklist first (fastest check)
        if (context.getDecisionStore().isBlocked(event.getSourceIp())) {
            return ThreatVerdict.block("engine", "IP is blacklisted",
                    event.getSourceIp(), 0);
        }
        if (event.getUserId() != null &&
                context.getDecisionStore().isBlocked("user:" + event.getUserId())) {
            return ThreatVerdict.block("engine", "User is blacklisted",
                    event.getUserId(), 0);
        }

        // Run through all enabled modules
        for (SecurityModule module : registry.getEnabledModules(context)) {
            try {
                ThreatVerdict verdict = module.analyzeRequest(event, context);

                if (verdict.isThreat()) {
                    if (properties.isActiveMode()) {
                        log.warn("[SentinAI] [{}] BLOCKED: {} — {}",
                                module.getId(), event, verdict.getReason());
                        // Store the block decision
                        if (verdict.shouldBlock()) {
                            context.getDecisionStore().block(
                                    verdict.getTargetIdentifier(),
                                    verdict.getReason(),
                                    verdict.getBlockDurationSeconds() > 0
                                            ? java.time.Duration.ofSeconds(verdict.getBlockDurationSeconds())
                                            : null);
                        }
                        return verdict;
                    } else {
                        // MONITOR mode — log but don't block
                        log.warn("[SentinAI] [{}] WOULD HAVE BLOCKED: {} — {}",
                                module.getId(), event, verdict.getReason());
                    }
                }
            } catch (Exception e) {
                log.error("[SentinAI] Module '{}' threw exception: {}",
                        module.getId(), e.getMessage());
                // Module failure should never crash the app
            }
        }

        // Buffer event for async batch analysis
        bufferEvent(event);

        return ThreatVerdict.safe("engine");
    }

    /**
     * Process an outgoing response through all enabled outbound modules.
     * Used for Data Leak Prevention, Cost Protection, etc.
     *
     * @return The (potentially modified) response.
     */
    public ResponseEvent processResponse(ResponseEvent response) {
        if (!properties.isEnabled()) {
            return response;
        }

        ResponseEvent current = response;
        for (SecurityModule module : registry.getEnabledModules(context)) {
            try {
                current = module.analyzeResponse(current, context);
            } catch (Exception e) {
                log.error("[SentinAI] Module '{}' response analysis failed: {}",
                        module.getId(), e.getMessage());
            }
        }
        return current;
    }

    /**
     * Buffer events and trigger batch analysis when buffer is full.
     */
    private void bufferEvent(RequestEvent event) {
        eventBuffer.add(event);
        if (eventBuffer.size() >= BATCH_SIZE) {
            List<RequestEvent> batch = new ArrayList<>(eventBuffer);
            eventBuffer.clear();
            asyncExecutor.execute(() -> runBatchAnalysis(batch));
        }
    }

    /**
     * Run async batch analysis across all modules.
     * This is where AI calls happen — it can take seconds.
     */
    private void runBatchAnalysis(List<RequestEvent> batch) {
        for (SecurityModule module : registry.getEnabledModules(context)) {
            try {
                List<ThreatVerdict> verdicts = module.analyzeBatch(batch, context);
                for (ThreatVerdict verdict : verdicts) {
                    if (verdict.shouldBlock()) {
                        log.warn("[SentinAI] [{}] Async BLOCK: {} — {}",
                                module.getId(), verdict.getTargetIdentifier(), verdict.getReason());

                        if (properties.isActiveMode()) {
                            context.getDecisionStore().block(
                                    verdict.getTargetIdentifier(),
                                    verdict.getReason(),
                                    verdict.getBlockDurationSeconds() > 0
                                            ? java.time.Duration.ofSeconds(verdict.getBlockDurationSeconds())
                                            : null);
                        }
                    }
                }
            } catch (Exception e) {
                log.error("[SentinAI] Module '{}' batch analysis failed: {}",
                        module.getId(), e.getMessage());
            }
        }
    }

    /**
     * Check if a path matches any exclusion pattern.
     */
    private boolean isExcludedPath(String path) {
        for (String pattern : properties.getExcludePaths()) {
            if (pattern.endsWith("/**")) {
                String prefix = pattern.substring(0, pattern.length() - 3);
                if (path.startsWith(prefix))
                    return true;
            } else if (pattern.equals(path)) {
                return true;
            }
        }
        return false;
    }

    /** Force flush the event buffer (for testing). */
    public void flushEventBuffer() {
        if (!eventBuffer.isEmpty()) {
            List<RequestEvent> batch = new ArrayList<>(eventBuffer);
            eventBuffer.clear();
            runBatchAnalysis(batch);
        }
    }
}
