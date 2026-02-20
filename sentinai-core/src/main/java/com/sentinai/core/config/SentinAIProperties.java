package com.sentinai.core.config;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Core configuration properties for SentinAI.
 * These map directly to the `sentinai.*` properties in your application.yml.
 */
public class SentinAIProperties {

    private boolean enabled = true;
    private String mode = "MONITOR"; // MONITOR or ACTIVE
    private List<String> excludePaths = List.of("/health", "/actuator/**");

    private AiProperties ai = new AiProperties();
    private StoreProperties store = new StoreProperties();
    private Map<String, ModuleProperties> modules = new HashMap<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public boolean isActiveMode() {
        return "ACTIVE".equalsIgnoreCase(mode);
    }

    public boolean isMonitorMode() {
        return "MONITOR".equalsIgnoreCase(mode);
    }

    public List<String> getExcludePaths() {
        return excludePaths;
    }

    public void setExcludePaths(List<String> excludePaths) {
        this.excludePaths = excludePaths;
    }

    public AiProperties getAi() {
        return ai;
    }

    public void setAi(AiProperties ai) {
        this.ai = ai;
    }

    public StoreProperties getStore() {
        return store;
    }

    public void setStore(StoreProperties store) {
        this.store = store;
    }

    public Map<String, ModuleProperties> getModules() {
        return modules;
    }

    public void setModules(Map<String, ModuleProperties> modules) {
        this.modules = modules;
    }

    /**
     * Useful for checking if a specific module is turned on.
     * Note: modules are enabled by default unless explicitly disabled.
     */
    public boolean isModuleEnabled(String moduleId) {
        ModuleProperties props = modules.get(moduleId);
        if (props == null)
            return true; // Modules are enabled by default if not explicitly turned off
        return props.isEnabled();
    }

    /**
     * Grab any custom settings specific to a module.
     */
    public Map<String, Object> getModuleConfig(String moduleId) {
        ModuleProperties props = modules.get(moduleId);
        if (props == null)
            return Map.of();
        return props.getConfig();
    }

    public static class AiProperties {
        private String provider = "openai";
        private String apiKey;
        private String model;
        private String baseUrl;

        public String getProvider() {
            return provider;
        }

        public void setProvider(String provider) {
            this.provider = provider;
        }

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getModel() {
            return model;
        }

        public void setModel(String model) {
            this.model = model;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }
    }

    public static class StoreProperties {
        private String type = "in-memory"; // "in-memory" or "redis"
        private String redisUrl = "redis://localhost:6379";

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getRedisUrl() {
            return redisUrl;
        }

        public void setRedisUrl(String redisUrl) {
            this.redisUrl = redisUrl;
        }
    }

    public static class ModuleProperties {
        private boolean enabled = true;
        private Map<String, Object> config = new HashMap<>();

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public Map<String, Object> getConfig() {
            return config;
        }

        public void setConfig(Map<String, Object> config) {
            this.config = config;
        }
    }
}
