package io.tomahawkd.cic;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.packet.PacketReader;
import io.tomahawkd.cic.util.Utils;
import io.tomahawkd.config.ConfigManager;
import io.tomahawkd.config.commandline.CommandlineConfig;
import io.tomahawkd.config.commandline.CommandlineConfigSource;
import io.tomahawkd.config.sources.SourceManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapClosedException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

public class Main {

    public static final Logger logger = LogManager.getLogger(Main.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";

    public static void main(String[] args) {
        SourceManager sourceManager = SourceManager.get();
        ConfigManager configManager = ConfigManager.get();

        sourceManager.getSource(CommandlineConfigSource.class).setData(args);
        configManager.parse();

        CommandlineDelegate delegate = configManager.getDelegateByType(CommandlineDelegate.class);
        assert delegate != null;
        if (delegate.isHelp()) {
            System.out.println(Objects.requireNonNull(configManager.getConfig(CommandlineConfig.class)).usage());
            return;
        }
        logger.debug("Commandline parse complete.");

        long flowTimeout = delegate.getFlowTimeout();
        long activityTimeout = delegate.getActivityTimeout();
        Map<Path, Path> inputOutputPaths = delegate.getInputOutputPaths();
        boolean oneFile = delegate.isOneFile();
        logger.debug("Parsed settings: ");
        logger.debug("Flow timeout: {}", flowTimeout);
        logger.debug("Activity timeout: {}", activityTimeout);
        logger.debug("Output one file: {}", oneFile);
        logger.debug("Pcap paths: [{}]", StringUtils.join(inputOutputPaths.keySet(), ","));
        if (oneFile) {
            logger.debug("Output path: {}", delegate.getOutputPath());
        } else {
            logger.debug("Output paths: [{}]", StringUtils.join(inputOutputPaths.values(), ","));
        }

        try {
            if (oneFile) {
                initFile(delegate.getOutputPath());
            }
            inputOutputPaths.forEach((inputFile, outputPath) -> {
                if (!oneFile) {
                    initFile(outputPath);
                }

                logger.info("Start Processing {}", inputFile.getFileName().toString());
                readPcapFile(inputFile, outputPath, flowTimeout, activityTimeout);
            });
        } catch (Exception e) {
            logger.fatal("Unexpected Exception {}", e.getClass().toString());
            logger.fatal("Reason: {}", String.valueOf(e.getMessage()));
            e.printStackTrace();
        }
    }

    private static void readPcapFile(Path inputFile, Path outputPath, long flowTimeout, long activityTimeout) {
        if (inputFile == null || outputPath == null) {
            logger.fatal("Got a null path.");
            throw new RuntimeException("Got a null path.");
        }

        if (!Files.exists(inputFile) || !Files.exists(outputPath)) {
            logger.fatal("File not found. Status: input({}), output({})",
                    Files.exists(inputFile), Files.exists(outputPath));
            throw new RuntimeException("File not found.");
        }

        String fileName = inputFile.getFileName().toString();
        System.out.printf("Working on... %s%n", fileName);

        // setting up
        FlowGenerator flowGen = new FlowGenerator(flowTimeout, activityTimeout);

        // This is hard-coded
        if (inputFile.getFileName().toString().contains("Wednesday-WorkingHours")) {
            // 172.16.0.1 -> 192.168.10.50:80
            flowGen.setFlowLabelSupplier(f -> {
                if (f.getSrc().equals("172.16.0.1") && f.getDst().equals("192.168.10.50") && f.getDstPort() == 80) {
                    return "SLOWDOS";
                } else return "NORMAL";
            });
        } else if (inputFile.getFileName().toString().contains("Friday-WorkingHours")) {
            flowGen.setFlowLabelSupplier(f -> {
                if (f.getSrc().equals("172.16.0.1") && f.getDst().equals("192.168.10.50") && f.getDstPort() == 80) {
                    return "DOS";
                } else return "NORMAL";
            });
        } else {
            flowGen.setFlowLabelSupplier(f -> "NONE");
        }

        // counter
        AtomicLong flowCount = new AtomicLong(0);
        flowGen.addFlowListener(flow -> flowCount.incrementAndGet());
        // data export
        flowGen.addFlowListener(flow -> Utils.insertToFile(flow.exportData(), outputPath));

        PacketReader packetReader = new PacketReader(inputFile.toString());
        long nTotal = 0;
        long nValid = 0;
        while (true) {
            try {
                PacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if (basicPacket != null) {
                    flowGen.addPacket(basicPacket);
                    nValid++;
                }
                System.out.printf("%s -> %d packets, %d flows \r", fileName, nTotal, flowCount.get());
            } catch (PcapClosedException e) {
                break;
            }
        }

        flowGen.dumpLabeledCurrentFlow();

        System.out.printf("%s is done. total %d flows %n", fileName, flowCount.get());
        System.out.printf("Packet stats: Total=%d,Valid=%d,Discarded=%d%n", nTotal, nValid, nTotal - nValid);
        System.out.println(DividingLine);
    }

    private static void initFile(Path file) {
        if (Files.exists(file)) {
            logger.info("File already exists. Removing...");
            try {
                Files.delete(file);
            } catch (IOException e) {
                logger.fatal("Save file {} can not be deleted.", file.toString(), e);
                throw new RuntimeException("Save file {} can not be deleted.", e);
            }
        }

        try {
            logger.info("Creating file {}...", file.getFileName().toString());
            Utils.initFile(file, Flow.getHeaders());
        } catch (IOException e) {
            logger.fatal("Failed to create file");
            throw new RuntimeException(e);
        }
    }
}
