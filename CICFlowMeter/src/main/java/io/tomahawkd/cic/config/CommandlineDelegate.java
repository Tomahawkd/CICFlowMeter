package io.tomahawkd.cic.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import io.tomahawkd.cic.execute.ExecutionMode;
import io.tomahawkd.cic.util.Utils;
import io.tomahawkd.config.AbstractConfigDelegate;
import io.tomahawkd.config.annotation.BelongsTo;
import io.tomahawkd.config.annotation.HiddenField;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    @HiddenField
    private List<String> pcapPathStringList = new ArrayList<>();
    private List<Path> pcapPath = new ArrayList<>();

    @Parameter(required = true,
            names = {"-o", "-output"},
            description = "Output directory.",
            converter = DirPathConverter.class)
    private Path outputPath;

    private Map<Path, Path> inputOutputPaths = new HashMap<>();

    @Parameter(names = {"-1", "--one_file"}, description = "Output only one file.")
    private boolean oneFile;

    @Parameter(names = {"-n", "--no"}, description = "Ignores specific feature (use as -no <feature1>,<feature2>)")
    private List<String> ignoreList = new ArrayList<>();

    @Parameter(names = {"-m", "--mode"}, description = "Mode selection.", converter = ExecutionModeConverter.class)
    private ExecutionMode mode = ExecutionMode.DEFAULT;

    @Parameter(names = {"--noassemble"}, description = "Disable TCP Reassembing")
    private boolean disableReassemble;

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

    public Map<Path, Path> getInputOutputPaths() {
        return inputOutputPaths;
    }

    public boolean isOneFile() {
        return oneFile;
    }

    public List<String> getIgnoreList() {
        return ignoreList;
    }

    public ExecutionMode getMode() {
        return mode;
    }

    public boolean isDisableReassemble() {
        return disableReassemble;
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
        if (oneFile) {
            outputPath = outputPath.resolve(Utils.DEFAULT_OUTPUT_FILENAME_PREFIX + Utils.FLOW_SUFFIX);
        }
        for (String pathString : pcapPathStringList) {
            Path p = Paths.get(pathString);
            if (!Files.exists(p)) continue;
            if (Files.isDirectory(p)) {
                try (Stream<Path> entries = Files.list(p)) {
                    entries.filter(Files::isRegularFile)
                            .filter(fl -> {
                                try {
                                    return Utils.PCAP.equalsIgnoreCase(new Tika().detect(fl));
                                } catch (IOException e) {
                                    return false;
                                }
                            })
                            .forEach(fl -> {
                                if (oneFile) {
                                    inputOutputPaths.put(fl, outputPath);
                                } else {
                                    inputOutputPaths.put(fl, outputPath.resolve(fl.getFileName().toString() + Utils.FLOW_SUFFIX));
                                }
                            });
                } catch (IOException e) {
                    System.err.println("Error occured while opening the directory: " + p.toAbsolutePath().toString());
                    throw new ParameterException(e);
                }
            } else if (Files.isRegularFile(p)) {
                boolean isPcap = false;
                try {
                    isPcap = Utils.PCAP.equalsIgnoreCase(new Tika().detect(p));
                } catch (IOException ignored) {
                }
                if (isPcap) {
                    inputOutputPaths.put(p, outputPath.resolve(p.getFileName().toString() + Utils.FLOW_SUFFIX));
                    pcapPath.add(p);
                } else {
                    System.err.println("Not a Pcap file: " + p.toAbsolutePath().toString());
                    throw new ParameterException("Not a Pcap file: " + p.toAbsolutePath().toString());
                }
            } else {
                System.err.println("Path is not a regular file or directory: " + p.toAbsolutePath().toString());
                throw new ParameterException("Path is not a regular file or directory: " +
                        p.toAbsolutePath().toString());
            }
        }

        // execution mode
        if (mode == ExecutionMode.DEFAULT) {
            mode = ExecutionMode.FULL;
        }
    }

    public String debugString() {
        StringBuilder builder = new StringBuilder();

        builder.append("Parsed settings: ").append("\n");
        builder.append("Execution mode: ").append(mode.toString()).append("\n");
        builder.append("Flow timeout: ").append(flowTimeout).append("\n");
        builder.append("Activity timeout: ").append(activityTimeout).append("\n");
        builder.append("Disable TCP Reassembling: ").append(disableReassemble).append("\n");
        builder.append("Output one file: ").append(oneFile).append("\n");
        builder.append("Data output: ").append("\n");
        inputOutputPaths.forEach((k, v) -> builder.append("\t").append(k).append(" -> ").append(v).append("\n"));
        if (oneFile) {
            builder.append("Output path (one file): ").append(outputPath).append("\n");
        }
        builder.append("Ignore List: [").append(ignoreList.stream().reduce("", (r, e) -> r + "," + e)).append("]").append("\n");

        return builder.toString();
    }
}