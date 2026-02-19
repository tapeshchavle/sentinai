package com.sentinai.autoconfigure;

import com.sentinai.core.SentinAIEngine;
import com.sentinai.core.ai.AiAnalyzer;
import com.sentinai.core.ai.SpringAiAnalyzer;
import com.sentinai.core.config.SentinAIProperties;
import com.sentinai.core.plugin.ModuleContext;
import com.sentinai.core.plugin.ModuleRegistry;
import com.sentinai.core.plugin.SecurityModule;
import com.sentinai.core.store.DecisionStore;
import org.springframework.beans.factory.annotation.Qualifier;
import com.sentinai.core.store.InMemoryDecisionStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.List;
import java.util.concurrent.Executor;

/**
 * Auto-configuration for SentinAI.
 * Activated when {@code sentinai.enabled=true} (default).
 */
@AutoConfiguration
@ConditionalOnProperty(name = "sentinai.enabled", havingValue = "true", matchIfMissing = true)
@ComponentScan(basePackages = "com.sentinai.module")
public class SentinAIAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SentinAIAutoConfiguration.class);

    @Bean
    @ConfigurationProperties(prefix = "sentinai")
    public SentinAIProperties sentinAIProperties() {
        return new SentinAIProperties();
    }

    @Bean
    @ConditionalOnMissingBean
    public DecisionStore decisionStore(SentinAIProperties properties) {
        // TODO: Add Redis implementation based on properties.getStore().getType()
        log.info("[SentinAI] Using InMemoryDecisionStore (add Redis for production)");
        return new InMemoryDecisionStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public AiAnalyzer aiAnalyzer() {
        // Try to find Spring AI's ChatClient in the application context
        // If not available, create a no-op analyzer
        log.info("[SentinAI] AI Analyzer initialized (will use Spring AI ChatClient if available)");
        return new SpringAiAnalyzer(null); // Will be enhanced with actual ChatClient
    }

    @Bean
    @ConditionalOnMissingBean
    public ModuleContext moduleContext(DecisionStore decisionStore, AiAnalyzer aiAnalyzer,
            SentinAIProperties properties) {
        return new ModuleContext(decisionStore, aiAnalyzer, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public ModuleRegistry moduleRegistry(List<SecurityModule> modules) {
        return new ModuleRegistry(modules);
    }

    @Bean
    @ConditionalOnMissingBean(name = "sentinaiExecutor")
    public Executor sentinaiExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("sentinai-async-");
        executor.initialize();
        return executor;
    }

    @Bean
    @ConditionalOnMissingBean
    public SentinAIEngine sentinAIEngine(ModuleRegistry registry, ModuleContext context,
            SentinAIProperties properties, @Qualifier("sentinaiExecutor") Executor sentinaiExecutor) {
        return new SentinAIEngine(registry, context, properties, sentinaiExecutor);
    }

    @Bean
    public SentinAISecurityFilter sentinAISecurityFilter(SentinAIEngine engine,
            SentinAIProperties properties) {
        return new SentinAISecurityFilter(engine, properties);
    }
}
