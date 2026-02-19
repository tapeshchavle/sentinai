package com.sentinai.core.plugin;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ResponseEvent;
import com.sentinai.core.model.ThreatVerdict;

import java.util.List;

/**
 * The core plugin interface that all SentinAI security modules must implement.
 * Each module focuses on one type of threat detection.
 *
 * <p>
 * Modules are discovered automatically via Spring's component scanning.
 * Simply annotate your implementation with {@code @Component}.
 * </p>
 *
 * <p>
 * <b>Lifecycle:</b>
 * </p>
 * <ol>
 * <li>{@link #analyzeRequest} — Called synchronously BEFORE the request reaches
 * the controller.</li>
 * <li>{@link #analyzeResponse} — Called synchronously AFTER the response is
 * generated.</li>
 * <li>{@link #analyzeBatch} — Called asynchronously at regular intervals with
 * recent events.</li>
 * </ol>
 */
public interface SecurityModule {

    /**
     * Unique identifier for this module. Used in configuration keys:
     * {@code sentinai.modules.{id}.enabled}
     */
    String getId();

    /**
     * Human-readable name for logging and dashboards.
     */
    String getName();

    /**
     * Priority order. Lower values execute first.
     * Default modules use: 100 (credential-guard), 200 (query-shield), etc.
     */
    default int getOrder() {
        return 500;
    }

    /**
     * Called synchronously for each incoming request BEFORE it reaches the
     * downstream service.
     * This method should be FAST (< 5ms). Do not call the AI here.
     *
     * @param event   The captured request metadata
     * @param context Shared state (decision store, configuration)
     * @return A verdict. Return {@link ThreatVerdict#safe(String)} to pass through.
     */
    ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext context);

    /**
     * Called synchronously for each outgoing response BEFORE it reaches the client.
     * Used by outbound modules (e.g., Data Leak Prevention) to scan/modify
     * responses.
     *
     * @param response The captured response metadata
     * @param context  Shared state
     * @return The response, potentially modified (e.g., with redacted fields).
     *         Return the original response if no changes needed.
     */
    default ResponseEvent analyzeResponse(ResponseEvent response, ModuleContext context) {
        return response; // Default: no modification
    }

    /**
     * Called asynchronously at regular intervals with a batch of recent events.
     * This is where AI analysis happens — it can take seconds and won't block any
     * requests.
     *
     * @param events  Batch of recent request events
     * @param context Shared state
     * @return List of verdicts for any threats found in the batch.
     */
    default List<ThreatVerdict> analyzeBatch(List<RequestEvent> events, ModuleContext context) {
        return List.of(); // Default: no batch analysis
    }

    /**
     * Whether this module is enabled. Checked against configuration.
     */
    default boolean isEnabled(ModuleContext context) {
        return context.getProperties().isModuleEnabled(getId());
    }
}
