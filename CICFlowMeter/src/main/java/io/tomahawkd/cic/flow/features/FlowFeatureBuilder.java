package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.config.util.ClassManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public enum FlowFeatureBuilder {

    INSTANCE;

    static Logger logger;
    static List<Class<? extends FlowFeature>> cachedFeatureClass;

    FlowFeatureBuilder() {
        init();
    }

    private void init() {
        logger = LogManager.getLogger(FlowFeatureBuilder.class);
        if (cachedFeatureClass == null) {
            cachedFeatureClass =
                    new ArrayList<>(ClassManager.createManager(null)
                            .loadClasses(FlowFeature.class, "io.tomahawkd.cic.flow.features"))
                            .stream()
                            .filter(f -> !Modifier.isAbstract(f.getModifiers()))
                            .filter(f -> !Modifier.isInterface(f.getModifiers()))
                            .filter(f -> f.getAnnotation(Feature.class) != null)
                            .peek(f -> logger.debug("Loading class {}", f.getName()))
                            .sorted(Comparator.comparingInt(f -> f.getAnnotation(Feature.class).ordinal()))
                            .collect(Collectors.toList());
        }
    }

    // call this AFTER the manually init class has been added to features
    public void buildClasses(Flow flow) {

        cachedFeatureClass.forEach(c -> {
            Feature feature = c.getAnnotation(Feature.class);
            if (!feature.manual()) {
                try {
                    logger.debug("Creating instance of class {}", c.getName());
                    FlowFeature newFeature = c.getConstructor(Flow.class).newInstance(flow);
                    flow.addFeature(newFeature);
                } catch (NoSuchMethodException | InstantiationException |
                        IllegalAccessException | InvocationTargetException e) {
                    logger.error("Cannot create new instance of {}", c, e);
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    flow.getDep(c);
                } catch (IllegalArgumentException e) {
                    logger.error("A manually created feature {} is not found in the list.", c.getName());
                    throw e;
                }
            }
        });

    }
}
