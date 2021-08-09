package io.tomahawkd.cic.label;

import io.tomahawkd.cic.label.factory.LabelFactory;
import io.tomahawkd.cic.label.factory.LabelStrategyFactory;
import io.tomahawkd.cic.source.LocalFile;
import io.tomahawkd.config.util.ClassManager;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

public class LabelStrategyFactoryManager {

    public static LabelStrategyFactoryManager get() {
        return new LabelStrategyFactoryManager();
    }


    private LabelStrategyFactoryManager() {
        if (ManagerInstance.INSTANCE.initialized) return;

        ClassManager.createManager(null)
                .loadClassesWithAnnotation(LabelStrategyFactory.class, null, LabelFactory.class)
                .stream().filter(c -> !Modifier.isAbstract(c.getModifiers()))
                .map(c -> {

                    try {
                        // construct config
                        Constructor<? extends LabelStrategyFactory> constructor = c.getDeclaredConstructor();
                        constructor.setAccessible(true);

                        return constructor.newInstance();
                    } catch (InstantiationException | InvocationTargetException |
                            NoSuchMethodException | IllegalAccessException e) {
                        throw new RuntimeException("Construct config " + c.getName() + " failed.", e);
                    }
                }).forEach(ManagerInstance.INSTANCE.factories::add);

        ManagerInstance.INSTANCE.initialized = true;
    }

    private enum ManagerInstance {
        INSTANCE;

        private boolean initialized;
        private final List<LabelStrategyFactory> factories;

        ManagerInstance() {
            factories = new ArrayList<>();
        }
    }

    public LabelStrategy getStrategy(LocalFile file) {
        for (LabelStrategyFactory factory : ManagerInstance.INSTANCE.factories) {
            LabelStrategy strategy = factory.getStrategy(file);
            if (strategy != LabelStrategy.NONE) {
                return strategy;
            }
        }
        return LabelStrategy.DEFAULT;
    }
}
