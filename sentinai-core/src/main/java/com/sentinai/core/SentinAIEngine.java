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
 * The brain of SentinAI.
 * This class runs all of our active SecurityModules against every request and
 * response.
 */
public class SentinAIEngine {

    private static final Logger log = LoggerFactory.getLogger(SentinAIEngine.class);

    private final ModuleRegistry registry;
    private final ModuleContext context;
    private final SentinAIProperties properties;
    private final Executor asyncExecutor;

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
     * Run an incoming request through our active inbound modules.
     * This is called synchronously on every request, so it needs to be fast.
     *
     * @return The first blocking verdict we find, or a safe verdict if it passes
     *         everything.
     */
    public ThreatVerdict processRequest(RequestEvent event) {
        if (!properties.isEnabled()) {
            return ThreatVerdict.safe("engine");
        }

        if (isExcludedPath(event.getPath())) {
            return ThreatVerdict.safe("engine");
        }

        if (context.getDecisionStore().isBlocked(event.getSourceIp())) {
            return ThreatVerdict.block("engine", "IP is blacklisted",
                    event.getSourceIp(), 0);
        }
        if (event.getUserId() != null &&
                context.getDecisionStore().isBlocked("user:" + event.getUserId())) {
            return ThreatVerdict.block("engine", "User is blacklisted",
                    event.getUserId(), 0);
        }

        for (SecurityModule module : registry.getEnabledModules(context)) {
            try {
                ThreatVerdict verdict = module.analyzeRequest(event, context);

                if (verdict.isThreat()) {
                    if (properties.isActiveMode()) {
                        log.warn("[SentinAI] [{}] BLOCKED: {} — {}",
                                module.getId(), event, verdict.getReason());
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
                        // We're just monitoring, so don't actually block the request, just log it
                        log.warn("[SentinAI] [{}] WOULD HAVE BLOCKED: {} — {}",
                                module.getId(), event, verdict.getReason());
                    }
                }
            } catch (Exception e) {
                log.error("[SentinAI] Module '{}' threw exception: {}",
                        module.getId(), e.getMessage());
                // Even if a module throws an exception, we shouldn't bring down the main app
            }
        }

        bufferEvent(event);

        return ThreatVerdict.safe("engine");
    }

    /**
     * Run an outgoing response through our active outbound modules.
     * This is how we handle Data Leak Prevention and Cost Protection.
     *
     * @return The response, which might be modified (e.g., redacted).
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
     * Keep adding events to our queue until it's full enough to run a batch
     * analysis.
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
     * Run batch analysis across all modules in a background thread.
     * We do this because AI calls can take several seconds to complete.
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
     * See if the requested path matches any of our configured exclude patterns.
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

    /** Flush any pending events in the buffer. Mostly useful for testing. */
    public void flushEventBuffer() {
        if (!eventBuffer.isEmpty()) {
            List<RequestEvent> batch = new ArrayList<>(eventBuffer);
            eventBuffer.clear();
            runBatchAnalysis(batch);
        }
    }
}
