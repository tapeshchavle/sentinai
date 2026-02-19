package com.sentinai.core.store;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * In-memory implementation of DecisionStore for development and single-instance
 * deployments.
 * Not suitable for multi-instance production deployments (use Redis instead).
 */
public class InMemoryDecisionStore implements DecisionStore {

    private static final Logger log = LoggerFactory.getLogger(InMemoryDecisionStore.class);

    private final Map<String, BlockEntry> blockedTargets = new ConcurrentHashMap<>();
    private final Map<String, CounterEntry> counters = new ConcurrentHashMap<>();
    private final Map<String, DataEntry> dataStore = new ConcurrentHashMap<>();

    @Override
    public boolean isBlocked(String targetIdentifier) {
        BlockEntry entry = blockedTargets.get(targetIdentifier);
        if (entry == null)
            return false;
        if (entry.isExpired()) {
            blockedTargets.remove(targetIdentifier);
            return false;
        }
        return true;
    }

    @Override
    public void block(String targetIdentifier, String reason, Duration duration) {
        Instant expiry = duration != null ? Instant.now().plus(duration) : Instant.MAX;
        blockedTargets.put(targetIdentifier, new BlockEntry(reason, expiry));
        log.info("[SentinAI] BLOCKED '{}' — Reason: {} — Duration: {}",
                targetIdentifier, reason, duration != null ? duration : "permanent");
    }

    @Override
    public void unblock(String targetIdentifier) {
        blockedTargets.remove(targetIdentifier);
        log.info("[SentinAI] UNBLOCKED '{}'", targetIdentifier);
    }

    @Override
    public long incrementCounter(String key, Duration window) {
        counters.compute(key, (k, existing) -> {
            if (existing == null || existing.isExpired()) {
                return new CounterEntry(1, Instant.now().plus(window));
            }
            existing.increment();
            return existing;
        });
        return counters.get(key).getCount();
    }

    @Override
    public long getCounter(String key) {
        CounterEntry entry = counters.get(key);
        if (entry == null || entry.isExpired())
            return 0;
        return entry.getCount();
    }

    @Override
    public void put(String key, String value, Duration ttl) {
        Instant expiry = ttl != null ? Instant.now().plus(ttl) : Instant.MAX;
        dataStore.put(key, new DataEntry(value, expiry));
    }

    @Override
    public String get(String key) {
        DataEntry entry = dataStore.get(key);
        if (entry == null || entry.isExpired())
            return null;
        return entry.value;
    }

    @Override
    public Map<String, String> getAllBlocked() {
        return blockedTargets.entrySet().stream()
                .filter(e -> !e.getValue().isExpired())
                .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().reason));
    }

    // --- Internal classes ---

    private static class BlockEntry {
        final String reason;
        final Instant expiry;

        BlockEntry(String reason, Instant expiry) {
            this.reason = reason;
            this.expiry = expiry;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiry);
        }
    }

    private static class CounterEntry {
        private final AtomicLong count;
        private final Instant expiry;

        CounterEntry(long initial, Instant expiry) {
            this.count = new AtomicLong(initial);
            this.expiry = expiry;
        }

        void increment() {
            count.incrementAndGet();
        }

        long getCount() {
            return count.get();
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiry);
        }
    }

    private static class DataEntry {
        final String value;
        final Instant expiry;

        DataEntry(String value, Instant expiry) {
            this.value = value;
            this.expiry = expiry;
        }

        boolean isExpired() {
            return Instant.now().isAfter(expiry);
        }
    }
}
