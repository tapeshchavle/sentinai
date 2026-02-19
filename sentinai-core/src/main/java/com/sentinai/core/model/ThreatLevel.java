package com.sentinai.core.model;

/**
 * Threat severity levels determined by SentinAI analysis.
 */
public enum ThreatLevel {

    /** Request appears safe. No action needed. */
    SAFE,

    /** Request is slightly suspicious. Log and monitor. */
    LOW,

    /** Request shows suspicious patterns. May warrant a challenge. */
    MEDIUM,

    /** Request is likely malicious. Should be blocked or challenged. */
    HIGH,

    /** Request is confirmed malicious. Must be blocked immediately. */
    CRITICAL
}
