package com.sentinai.core.model;

import java.time.Instant;

/**
 * The AI's decision about a request or batch of requests.
 */
public class ThreatVerdict {

    private final ThreatLevel level;
    private final String reason;
    private final String moduleId; // Which module produced this verdict
    private final Action recommendedAction;
    private final String targetIdentifier; // What to block (IP, userId, fingerprint)
    private final long blockDurationSeconds; // How long to block (0 = permanent)
    private final Instant timestamp;

    public enum Action {
        ALLOW, // Let the request through
        LOG, // Allow but log a warning
        CHALLENGE, // Respond with CAPTCHA or crypto challenge
        THROTTLE, // Slow down the client
        BLOCK // Reject the request
    }

    private ThreatVerdict(ThreatLevel level, String reason, String moduleId,
            Action action, String targetIdentifier, long blockDurationSeconds) {
        this.level = level;
        this.reason = reason;
        this.moduleId = moduleId;
        this.recommendedAction = action;
        this.targetIdentifier = targetIdentifier;
        this.blockDurationSeconds = blockDurationSeconds;
        this.timestamp = Instant.now();
    }

    // --- Factory methods for easy creation ---

    public static ThreatVerdict safe(String moduleId) {
        return new ThreatVerdict(ThreatLevel.SAFE, "No threat detected", moduleId,
                Action.ALLOW, null, 0);
    }

    public static ThreatVerdict suspicious(String moduleId, String reason, String target) {
        return new ThreatVerdict(ThreatLevel.MEDIUM, reason, moduleId,
                Action.LOG, target, 0);
    }

    public static ThreatVerdict challenge(String moduleId, String reason, String target) {
        return new ThreatVerdict(ThreatLevel.HIGH, reason, moduleId,
                Action.CHALLENGE, target, 0);
    }

    public static ThreatVerdict block(String moduleId, String reason, String target, long durationSeconds) {
        return new ThreatVerdict(ThreatLevel.CRITICAL, reason, moduleId,
                Action.BLOCK, target, durationSeconds);
    }

    public static ThreatVerdict throttle(String moduleId, String reason, String target) {
        return new ThreatVerdict(ThreatLevel.HIGH, reason, moduleId,
                Action.THROTTLE, target, 0);
    }

    // --- Getters ---
    public ThreatLevel getLevel() {
        return level;
    }

    public String getReason() {
        return reason;
    }

    public String getModuleId() {
        return moduleId;
    }

    public Action getRecommendedAction() {
        return recommendedAction;
    }

    public String getTargetIdentifier() {
        return targetIdentifier;
    }

    public long getBlockDurationSeconds() {
        return blockDurationSeconds;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public boolean isThreat() {
        return level != ThreatLevel.SAFE && level != ThreatLevel.LOW;
    }

    public boolean shouldBlock() {
        return recommendedAction == Action.BLOCK;
    }

    @Override
    public String toString() {
        return "ThreatVerdict{" +
                "level=" + level +
                ", action=" + recommendedAction +
                ", module='" + moduleId + '\'' +
                ", reason='" + reason + '\'' +
                ", target='" + targetIdentifier + '\'' +
                '}';
    }
}
