package com.sentinai.module.bola;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ThreatVerdict;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.SecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Detects Broken Object Level Authorization (BOLA) attacks.
 *
 * We spot when a user tries to access resources they don't own by:
 * 1. Keeping an eye on which resource IDs each user normally accesses
 * 2. Catching people rapidly enumerating IDs (like trying /api/users/1, then 2,
 * then 3...)
 * 3. Flagging sessions that suddenly touch way too many unique IDs
 */
@Component
public class BolaDetectionModule implements SecurityModule {

    private static final Logger log = LoggerFactory.getLogger(BolaDetectionModule.class);
    private static final String ID = "bola-detection";

    // Default resource path patterns: /api/users/{id}, /api/orders/{id}
    private static final Pattern PATH_ID_PATTERN = Pattern.compile("/api/\\w+/([0-9]+)");
    private static final Pattern PATH_UUID_PATTERN = Pattern
            .compile("/api/\\w+/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})");

    private static final Duration TRACKING_WINDOW = Duration.ofMinutes(10);
    private static final int DEFAULT_UNIQUE_ID_THRESHOLD = 15; // 15 unique IDs in 10 min = suspicious
    private static final int DEFAULT_SEQUENTIAL_THRESHOLD = 5; // 5 sequential IDs = enumeration

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getName() {
        return "BOLA Detection";
    }

    @Override
    public int getOrder() {
        return 300;
    }

    @Override
    public boolean isEnabled(ModuleContext context) {
        // BOLA detection requires explicit configuration (or auto-detect mode)
        return context.getProperties().isModuleEnabled(ID);
    }

    @Override
    public ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext context) {
        // Unauthenticated folks can't do BOLA, so ignore them
        if (event.getUserId() == null) {
            return ThreatVerdict.safe(ID);
        }

        // Pull the ID out of the URL path
        String resourceId = extractResourceId(event.getPath());
        if (resourceId == null) {
            return ThreatVerdict.safe(ID);
        }

        String userKey = "bola:user:" + event.getUserId();
        String idsKey = userKey + ":ids";

        if (context.getDecisionStore().isBlocked(userKey)) {
            return ThreatVerdict.block(ID,
                    "User blocked for BOLA attack",
                    event.getUserId(),
                    Duration.ofMinutes(60).toSeconds());
        }

        context.getDecisionStore()
                .incrementCounter(idsKey + ":" + resourceId, TRACKING_WINDOW);

        // See how many unique IDs they've accessed total
        long totalUniqueAccesses = context.getDecisionStore()
                .incrementCounter(idsKey + ":total", TRACKING_WINDOW);

        int uniqueThreshold = getUniqueIdThreshold(context);
        if (totalUniqueAccesses > uniqueThreshold) {
            log.warn(
                    "[SentinAI] [bola-detection] User '{}' accessed {} unique resource IDs in {} — possible enumeration",
                    event.getUserId(), totalUniqueAccesses, TRACKING_WINDOW);
            return ThreatVerdict.block(ID,
                    "BOLA: User accessed " + totalUniqueAccesses + " unique IDs in " + TRACKING_WINDOW,
                    event.getUserId(),
                    Duration.ofMinutes(30).toSeconds());
        }

        if (isNumericId(resourceId)) {
            long seqCount = trackSequentialAccess(event.getUserId(), Long.parseLong(resourceId), context);
            int seqThreshold = getSequentialThreshold(context);
            if (seqCount >= seqThreshold) {
                log.warn("[SentinAI] [bola-detection] User '{}' accessing sequential IDs: {} consecutive",
                        event.getUserId(), seqCount);
                return ThreatVerdict.block(ID,
                        "BOLA: Sequential ID enumeration detected (" + seqCount + " consecutive IDs)",
                        event.getUserId(),
                        Duration.ofMinutes(30).toSeconds());
            }
        }

        return ThreatVerdict.safe(ID);
    }

    @Override
    public List<ThreatVerdict> analyzeBatch(List<RequestEvent> events, ModuleContext context) {
        // Group these events by user so we can spot suspicious patterns looking across
        // the whole batch
        Map<String, List<RequestEvent>> byUser = events.stream()
                .filter(e -> e.getUserId() != null)
                .filter(e -> extractResourceId(e.getPath()) != null)
                .collect(Collectors.groupingBy(RequestEvent::getUserId));

        List<ThreatVerdict> verdicts = new ArrayList<>();

        for (var entry : byUser.entrySet()) {
            String userId = entry.getKey();
            List<RequestEvent> userEvents = entry.getValue();

            // How many distinct resource IDs did they hit?
            long uniqueIds = userEvents.stream()
                    .map(e -> extractResourceId(e.getPath()))
                    .distinct()
                    .count();

            if (uniqueIds > 10) {
                verdicts.add(ThreatVerdict.suspicious(ID,
                        "Batch analysis: user '" + userId + "' accessed " + uniqueIds + " unique IDs",
                        userId));
            }
        }

        return verdicts;
    }

    private String extractResourceId(String path) {
        if (path == null)
            return null;
        Matcher numericMatcher = PATH_ID_PATTERN.matcher(path);
        if (numericMatcher.find())
            return numericMatcher.group(1);
        Matcher uuidMatcher = PATH_UUID_PATTERN.matcher(path);
        if (uuidMatcher.find())
            return uuidMatcher.group(1);
        return null;
    }

    private boolean isNumericId(String id) {
        try {
            Long.parseLong(id);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private long trackSequentialAccess(String userId, long currentId, ModuleContext context) {
        String lastIdKey = "bola:seq:" + userId + ":last";
        String seqCountKey = "bola:seq:" + userId + ":count";

        String lastIdStr = context.getDecisionStore().get(lastIdKey);
        long lastId = lastIdStr != null ? Long.parseLong(lastIdStr) : -1;

        if (currentId == lastId + 1 || currentId == lastId - 1) {
            // Found a sequence! Bump the counter
            long count = context.getDecisionStore().incrementCounter(seqCountKey, TRACKING_WINDOW);
            context.getDecisionStore().put(lastIdKey, String.valueOf(currentId), TRACKING_WINDOW);
            return count;
        } else {
            // Break in the sequence, reset our counter
            context.getDecisionStore().put(lastIdKey, String.valueOf(currentId), TRACKING_WINDOW);
            context.getDecisionStore().put(seqCountKey, "0", TRACKING_WINDOW);
            return 0;
        }
    }

    private int getUniqueIdThreshold(ModuleContext context) {
        var config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("unique-id-threshold");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_UNIQUE_ID_THRESHOLD;
    }

    private int getSequentialThreshold(ModuleContext context) {
        var config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("sequential-threshold");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_SEQUENTIAL_THRESHOLD;
    }
}
