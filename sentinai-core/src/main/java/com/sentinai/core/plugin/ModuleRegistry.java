package com.sentinai.core.plugin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Discovers and manages all registered SecurityModules.
 * Modules are ordered by their {@link SecurityModule#getOrder()} priority.
 */
public class ModuleRegistry {

    private static final Logger log = LoggerFactory.getLogger(ModuleRegistry.class);

    private final List<SecurityModule> modules;
    private final Map<String, SecurityModule> moduleMap;

    public ModuleRegistry(List<SecurityModule> modules) {
        List<SecurityModule> sorted = new CopyOnWriteArrayList<>(modules);
        sorted.sort(Comparator.comparingInt(SecurityModule::getOrder));
        this.modules = Collections.unmodifiableList(sorted);
        this.moduleMap = modules.stream()
                .collect(Collectors.toMap(SecurityModule::getId, Function.identity()));

        log.info("[SentinAI] Registered {} security modules: {}",
                modules.size(),
                modules.stream().map(m -> m.getId() + "(order=" + m.getOrder() + ")")
                        .collect(Collectors.joining(", ")));
    }

    public List<SecurityModule> getModules() {
        return modules;
    }

    public SecurityModule getModule(String id) {
        return moduleMap.get(id);
    }

    public List<SecurityModule> getEnabledModules(ModuleContext context) {
        return modules.stream()
                .filter(m -> m.isEnabled(context))
                .collect(Collectors.toList());
    }

    public boolean hasModule(String id) {
        return moduleMap.containsKey(id);
    }
}
