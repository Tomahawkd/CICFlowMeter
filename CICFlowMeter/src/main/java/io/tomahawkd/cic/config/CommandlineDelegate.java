package io.tomahawkd.cic.config;

import io.tomahawkd.cic.jnetpcap.Utils;
import com.beust.jcommander.Parameter;
import io.tomahawkd.config.AbstractConfigDelegate;
import io.tomahawkd.config.annotation.BelongsTo;
import io.tomahawkd.config.commandline.CommandlineConfig;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.tika.Tika;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@SuppressWarnings("all")
@BelongsTo(CommandlineConfig.class)
public class CommandlineDelegate extends AbstractConfigDelegate {

    @Parameter(names = {"-h", "--help"}, help = true,
            description = "Prints usage for all the existing commands.")
    private boolean help;

    @Parameter(names = {"-f", "--flow_time"}, description = "Setting timeout interval for a flow.")
    private long flowTimeout = 120000000L;

    @Parameter(names = {"-a", "--act_time"}, description = "Setting timeout interval for an activity.")
    private long activityTimeout = 5000000L;

    @Parameter(names = "--debug", description = "Show debug output (sets logLevel to DEBUG)")
    private boolean debug = false;

    @Parameter(names = "--quiet", description = "No output (sets logLevel to NONE)")
    private boolean quiet = false;

    @Parameter(required = true, description = "Pcap file or directory.")
    private List<String> pcapPathStringList = new ArrayList<>();
    private List<Path> pcapPath = new ArrayList<>();

    @Parameter(required = true,
            names = {"-o", "-output"},
            description = "Output directory.",
            converter = DirPathConverter.class)
    private Path outputPath;

    public boolean isHelp() {
        return help;
    }

    public long getFlowTimeout() {
        return flowTimeout;
    }

    public long getActivityTimeout() {
        return activityTimeout;
    }

    public List<Path> getPcapPath() {
        return pcapPath;
    }

    public Path getOutputPath() {
        return outputPath;
    }

    @Override
    public void postParsing() {
        super.postParsing();

        if (debug) {
            LoggerContext ctx = LoggerContext.getContext(false);
            Configuration config = ctx.getConfiguration();
            LoggerConfig loggerConfig = config.getLoggerConfig("io.tomahawkd.cic");
            loggerConfig.removeAppender("Console");
            loggerConfig.addAppender(
                    config.getAppender("DebugConsole"), Level.DEBUG, null);
            ctx.updateLoggers();
            return;
        }

        if (quiet) {
            Configurator.setAllLevels("io.tomahawkd.cic", Level.OFF);
        }

        // input list
        for (String pathString : pcapPathStringList) {
            Path p = Paths.get(pathString);
            if (!Files.exists(p)) continue;
            if (Files.isDirectory(p)) {
                try (Stream<Path> entries = Files.list(p)) {
                    pcapPath.addAll(entries.filter(fl -> Files.isRegularFile(fl))
                            .filter(fl -> {
                                try {
                                    return Utils.PCAP.equalsIgnoreCase(new Tika().detect(fl));
                                } catch (IOException e) {
                                    return false;
                                }
                            }).collect(Collectors.toList()));
                } catch (IOException e) {
                    System.err.println("Error occured while opening the directory: " + p.toAbsolutePath().toString());
                }
            } else if (Files.isRegularFile(p)) {
                boolean isPcap = false;
                try {
                    isPcap = Utils.PCAP.equalsIgnoreCase(new Tika().detect(p));
                } catch (IOException ignored) {
                }
                if (isPcap) {
                    pcapPath.add(p);
                } else {
                    System.err.println("Not a Pcap file: " + p.toAbsolutePath().toString());
                }
            } else {
                System.err.println("Path is not a regular file or directory: " + p.toAbsolutePath().toString());
            }
        }
    }
}