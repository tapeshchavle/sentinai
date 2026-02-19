package com.sentinai.core.store;

import java.time.Duration;
import java.util.Map;

/**
 * Abstraction for storing security decisions (blacklists, counters, rate data).
 * Implementations: Redis (production) or InMemory (dev/testing).
 */
public interface DecisionStore {

    /**
     * Check if a target (IP, userId, fingerprint) is currently blocked.
     * Must be FAST (< 1ms for Redis, < 0.1ms for InMemory).
     */
    boolean isBlocked(String targetIdentifier);

    /**
     * Block a target for the specified duration.
     * 
     * @param targetIdentifier The IP, userId, or fingerprint to block
     * @param reason           Why it was blocked (for logging)
     * @param duration         How long to block. null = permanent.
     */
    void block(String targetIdentifier, String reason, Duration duration);

    /**
     * Remove a block on a target.
     */
    void unblock(String targetIdentifier);

    /**
     * Increment a counter for a key (e.g., "login_failures:john@email.com").
     * Returns the new count after incrementing.
     * Counter auto-expires after the given window.
     */
    long incrementCounter(String key, Duration window);

    /**
     * Get the current value of a counter.
     */
    long getCounter(String key);

    /**
     * Store arbitrary key-value data with optional TTL.
     */
    void put(String key, String value, Duration ttl);

    /**
     * Retrieve stored data.
     */
    String get(String key);

    /**
     * Get all currently blocked targets with their reasons.
     */
    Map<String, String> getAllBlocked();
}
