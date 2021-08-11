package io.tomahawkd.cic.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import io.tomahawkd.cic.execute.ExecutionMode;
import io.tomahawkd.cic.pcap.PcapFileReaderProvider;
import io.tomahawkd.cic.source.LocalFile;
import io.tomahawkd.cic.source.LocalMultiFile;
import io.tomahawkd.cic.source.LocalSingleFile;
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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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
    @HiddenField
    private List<String> pcapPathStringList = new ArrayList<>();

    @Parameter(required = true,
            names = {"-o", "-output"},
            description = "Output directory.",
            converter = DirPathConverter.class)
    private Path outputPath;

    private Map<LocalFile, Path> inputOutputPaths = new HashMap<>();

    @Parameter(names = {"-1", "--one_file"}, description = "Output only one file.")
    private boolean oneFile;

    @Parameter(names = {"-n", "--no"}, description = "Ignores specific feature (use as -no <feature1>,<feature2>)")
    private List<String> ignoreList = new ArrayList<>();

    @Parameter(names = {"-m", "--mode"}, description = "Mode selection.", converter = ExecutionModeConverter.class)
    private ExecutionMode mode = ExecutionMode.DEFAULT;

    @Parameter(names = {"--noassemble"}, description = "Disable TCP Reassembing")
    private boolean disableReassemble;

    @Parameter(names = {"-c", "--continue"}, description = "Indicate the files in input dir are continuous.")
    private boolean continuous;

    @Parameter(names = {"-t", "--flow_thread"}, description = "Set the thread count to process flows")
    private int flowThreads = 5;

    @Parameter(names = {"-q", "--flow_queue"}, description = "Set the queue length waiting for flow process")
    private long flowQueueSize = 256;

    @Parameter(names = {"--old"}, description = "Use Jnetpcap Parser which is stable but slow.")
    private boolean useOldParser = false;

    public boolean isHelp() {
        return help;
    }

    public long getFlowTimeout() {
        return flowTimeout;
    }

    public long getActivityTimeout() {
        return activityTimeout;
    }

    public Map<LocalFile, Path> getInputOutputPaths() {
        return inputOutputPaths;
    }

    public boolean isOneFile() {
        return oneFile;
    }

    public Path getOneFilePath() {
        return outputPath.resolve(Utils.DEFAULT_OUTPUT_FILENAME);
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

    public boolean isContinuous() {
        return continuous;
    }

    public int getFlowThreadCount() {
        return flowThreads;
    }

    public long getFlowQueueSize() {
        return flowQueueSize;
    }

    public boolean useOldParser() {
        return useOldParser;
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
                    List<Path> inputFiles = entries.filter(Files::isRegularFile)
                            .filter(fl -> {
                                try {
                                    return PcapFileReaderProvider.INSTANCE.isPcapFile(fl);
                                } catch (IOException e) {
                                    return false;
                                }
                            }).collect(Collectors.toList());
                    if (inputFiles.size() == 0) continue;

                    if (continuous) {
                        LocalFile file;
                        if (inputFiles.size() > 1) {
                            file = new LocalMultiFile(p);
                            ((LocalMultiFile) file).addSegments(inputFiles);
                        } else {
                            file = new LocalSingleFile(inputFiles.get(0));
                        }
                        inputOutputPaths.put(file, outputPath.resolve(generateOutputFileName(file, oneFile)));
                    } else {
                        inputFiles.forEach(f -> {
                            LocalFile file = new LocalSingleFile(f);
                            inputOutputPaths.put(file, outputPath.resolve(generateOutputFileName(file, oneFile)));
                        });
                    }
                } catch (IOException e) {
                    System.err.println("Error occured while opening the directory: " + p.toAbsolutePath().toString());
                    throw new ParameterException(e);
                }
            } else if (Files.isRegularFile(p)) {
                boolean isPcap = false;
                try {
                    isPcap = PcapFileReaderProvider.INSTANCE.isPcapFile(p);
                } catch (IOException ignored) {
                }
                if (isPcap) {
                    LocalFile file = new LocalSingleFile(p);
                    inputOutputPaths.put(file, outputPath.resolve(generateOutputFileName(file, oneFile)));
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

        // threads
        if (flowThreads < 1) flowThreads = 1;
        if (flowQueueSize < 0) flowQueueSize = 256;
    }

    private String generateOutputFileName(LocalFile input, boolean oneFile) {
        if (oneFile) {
            return Utils.DEFAULT_OUTPUT_FILENAME;
        } else {
            return input.getFileName() + Utils.FLOW_SUFFIX;
        }
    }

    public String debugString() {
        StringBuilder builder = new StringBuilder();

        builder.append("Parsed settings: ").append("\n");
        builder.append("Execution mode: ").append(mode.toString()).append("\n");
        builder.append("Flow timeout: ").append(flowTimeout).append("\n");
        builder.append("Activity timeout: ").append(activityTimeout).append("\n");
        builder.append("Disable TCP Reassembling: ").append(disableReassemble).append("\n");
        builder.append("Flow threads: ").append(flowThreads).append("\n");
        builder.append("Flow Queue Size: ").append(flowQueueSize).append("\n");
        builder.append("Use Old Packet Reader: ").append(useOldParser).append("\n");
        builder.append("Continuous File: ").append(continuous).append("\n");
        builder.append("Output one file: ").append(oneFile).append("\n");
        builder.append("Data output: ").append("\n");
        inputOutputPaths.forEach((k, v) -> builder.append("\t").append(k).append(" -> ").append(v).append("\n"));
        if (oneFile) {
            builder.append("Output path (one file): ").append(getOneFilePath()).append("\n");
        }
        builder.append("Ignore List: [").append(ignoreList.stream().reduce("", (r, e) -> r + "," + e)).append("]").append("\n");

        return builder.toString();
    }
}