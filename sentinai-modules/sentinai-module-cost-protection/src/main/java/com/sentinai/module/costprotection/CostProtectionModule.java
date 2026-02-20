package com.sentinai.module.costprotection;

import com.sentinai.core.model.RequestEvent;
import com.sentinai.core.model.ThreatVerdict;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.SecurityModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDate;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Prevents AI API bill shock.
 *
 * Keeps track of:
 * 1. Global daily spend (estimated based on tokens)
 * 2. How many requests each individual user has made
 * 3. Alerting admins when we're getting close to our budget limits
 */
@Component
public class CostProtectionModule implements SecurityModule {

    private static final Logger log = LoggerFactory.getLogger(CostProtectionModule.class);
    private static final String ID = "cost-protection";

    private static final double DEFAULT_DAILY_LIMIT = 50.0; // $50/day default
    private static final int DEFAULT_PER_USER_LIMIT = 100; // 100 AI calls/day/user
    private static final double DEFAULT_COST_PER_REQUEST = 0.003; // ~$0.003 per AI call
    private static final double DEFAULT_ALERT_THRESHOLD = 0.8; // Alert at 80%

    // Track daily spend
    private final AtomicLong dailyRequestCount = new AtomicLong(0);
    private volatile String currentDay = LocalDate.now().toString();

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getName() {
        return "Cost Protection";
    }

    @Override
    public int getOrder() {
        return 900;
    }

    @Override
    public boolean isEnabled(ModuleContext context) {
        // Only enabled if user explicitly configures a budget
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        return config.containsKey("daily-limit") || config.containsKey("enabled");
    }

    @Override
    public ThreatVerdict analyzeRequest(RequestEvent event, ModuleContext context) {
        // Only bother tracking requests that actually call our AI endpoints
        if (!isAiEndpoint(event)) {
            return ThreatVerdict.safe(ID);
        }

        // Start over if it's a new day
        resetIfNewDay();

        double dailyLimit = getDailyLimit(context);
        double costPerRequest = getCostPerRequest(context);
        double estimatedSpend = dailyRequestCount.get() * costPerRequest;

        if (estimatedSpend >= dailyLimit) {
            log.warn("[SentinAI] [cost-protection] Daily budget EXCEEDED: ${}/{} — blocking AI requests",
                    String.format("%.2f", estimatedSpend), String.format("%.0f", dailyLimit));
            return ThreatVerdict.throttle(ID,
                    "Daily AI budget exceeded ($" + String.format("%.2f", estimatedSpend) + "/$"
                            + String.format("%.0f", dailyLimit) + ")",
                    event.getSourceIp());
        }

        double alertThreshold = getAlertThreshold(context);
        if (estimatedSpend >= dailyLimit * alertThreshold) {
            log.warn("[SentinAI] [cost-protection] Budget alert: ${}/{} ({}%)",
                    String.format("%.2f", estimatedSpend),
                    String.format("%.0f", dailyLimit),
                    String.format("%.0f", (estimatedSpend / dailyLimit) * 100));
        }

        if (event.getUserId() != null) {
            int perUserLimit = getPerUserLimit(context);
            long userCount = context.getDecisionStore()
                    .incrementCounter("cp:user:" + event.getUserId(), Duration.ofDays(1));
            if (userCount > perUserLimit) {
                log.warn("[SentinAI] [cost-protection] User '{}' exceeded daily AI limit: {}/{}",
                        event.getUserId(), userCount, perUserLimit);
                return ThreatVerdict.throttle(ID,
                        "User daily AI limit exceeded (" + userCount + "/" + perUserLimit + ")",
                        "user:" + event.getUserId());
            }
        }

        // Add one more to the daily total
        dailyRequestCount.incrementAndGet();
        return ThreatVerdict.safe(ID);
    }

    private boolean isAiEndpoint(RequestEvent event) {
        String path = event.getPath().toLowerCase();
        return path.contains("/chat") || path.contains("/summarize") ||
                path.contains("/generate") || path.contains("/ai/") ||
                path.contains("/completion") || path.contains("/predict");
    }

    private void resetIfNewDay() {
        String today = LocalDate.now().toString();
        if (!today.equals(currentDay)) {
            synchronized (this) {
                if (!today.equals(currentDay)) {
                    dailyRequestCount.set(0);
                    currentDay = today;
                    log.info("[SentinAI] [cost-protection] Daily budget reset for {}", today);
                }
            }
        }
    }

    private double getDailyLimit(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("daily-limit");
        return val != null ? Double.parseDouble(val.toString()) : DEFAULT_DAILY_LIMIT;
    }

    private double getCostPerRequest(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("cost-per-request");
        return val != null ? Double.parseDouble(val.toString()) : DEFAULT_COST_PER_REQUEST;
    }

    private int getPerUserLimit(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("per-user-limit");
        return val != null ? Integer.parseInt(val.toString()) : DEFAULT_PER_USER_LIMIT;
    }

    private double getAlertThreshold(ModuleContext context) {
        Map<String, Object> config = context.getProperties().getModuleConfig(ID);
        Object val = config.get("alert-threshold");
        return val != null ? Double.parseDouble(val.toString()) : DEFAULT_ALERT_THRESHOLD;
    }
}
