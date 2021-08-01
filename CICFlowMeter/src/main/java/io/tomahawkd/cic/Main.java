package io.tomahawkd.cic;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.execute.ExecutionMode;
import io.tomahawkd.cic.execute.Executor;
import io.tomahawkd.cic.execute.WithMode;
import io.tomahawkd.cic.util.Utils;
import io.tomahawkd.config.ConfigManager;
import io.tomahawkd.config.commandline.CommandlineConfig;
import io.tomahawkd.config.commandline.CommandlineConfigSource;
import io.tomahawkd.config.sources.SourceManager;
import io.tomahawkd.config.util.ClassManager;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.lang.reflect.InvocationTargetException;
import java.util.Objects;

public class Main {

    public static final Logger logger = LogManager.getLogger(Main.class);

    public static void main(String[] args) {
        SourceManager sourceManager = SourceManager.get();
        ConfigManager configManager = ConfigManager.get();

        sourceManager.getSource(CommandlineConfigSource.class).setData(args);
        configManager.parse();

        CommandlineDelegate delegate = configManager.getDelegateByType(CommandlineDelegate.class);
        assert delegate != null;
        if (delegate.isHelp()) {
            System.out.println(Objects.requireNonNull(configManager.getConfig(CommandlineConfig.class)).usage());
            System.out.println("Mode Selection: ");
            System.out.println(ArrayUtils.toString(ExecutionMode.values()));
            return;
        }
        logger.debug("Commandline parse complete.");
        logger.debug(delegate.debugString());
        System.out.println(delegate.debugString());
        System.out.println(Utils.DividingLine);


        Class<? extends Executor> executorClass = ClassManager.createManager(null)
                .loadClassesWithAnnotation(Executor.class, null, WithMode.class)
                .stream()
                .filter(c -> ArrayUtils.contains(c.getAnnotation(WithMode.class).value(), delegate.getMode()))
                .findFirst().orElse(null);

        if (executorClass == null) {
            logger.fatal("Executor not found.");
            return;
        }

        try {
            Executor executor = executorClass.getDeclaredConstructor().newInstance();
            executor.execute(delegate);
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            logger.fatal("Cannot create executor {}", executorClass.getName(), e);
            e.printStackTrace();
        } catch (Exception e) {
            logger.fatal("Unexpect exception.", e);
            e.printStackTrace();
        }
    }
}
