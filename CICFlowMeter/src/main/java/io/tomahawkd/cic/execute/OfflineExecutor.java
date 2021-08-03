package io.tomahawkd.cic.execute;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.packet.PacketReader;
import io.tomahawkd.cic.util.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapClosedException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

@WithMode({ExecutionMode.SAMPLING, ExecutionMode.FULL})
public class OfflineExecutor extends AbstractExecutor {

    private static final Logger logger = LogManager.getLogger(OfflineExecutor.class);

    public OfflineExecutor() {
        super();
    }

    @Override
    public void execute(CommandlineDelegate delegate) throws Exception {

        long flowTimeout = delegate.getFlowTimeout();
        long activityTimeout = delegate.getActivityTimeout();
        Map<Path, Path> inputOutputPaths = delegate.getInputOutputPaths();
        boolean oneFile = delegate.isOneFile();
        Path oneOutputPath = delegate.getOutputPath();
        ExecutionMode mode = delegate.getMode();

        if (oneFile) {
            initFile(oneOutputPath);
            inputOutputPaths.forEach((inputFile, ignored) -> {
                logger.info("Start Processing {}", inputFile.getFileName().toString());
                readPcapFile(inputFile, oneOutputPath, flowTimeout, activityTimeout, mode);
            });
        } else {
            inputOutputPaths.forEach((inputFile, outputPath) -> {
                initFile(outputPath);
                logger.info("Start Processing {}", inputFile.getFileName().toString());
                readPcapFile(inputFile, outputPath, flowTimeout, activityTimeout, mode);
            });
        }
    }

    private static void readPcapFile(Path inputFile, Path outputPath, long flowTimeout, long activityTimeout, ExecutionMode mode) {
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
        FlowGenerator flowGen = new FlowGenerator(flowTimeout, activityTimeout, mode);

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
        } else if (inputFile.getFileName().toString().startsWith("IoT_Dataset_HTTP_")) {
            flowGen.setFlowLabelSupplier(f -> {
                if (f.connectBetween("192.168.100.150", Flow.PORT_ANY, "192.168.100.6", 80) ||
                        f.connectBetween("192.168.100.149", Flow.PORT_ANY, "192.168.100.5", 80) ||
                        f.connectBetween("192.168.100.148", Flow.PORT_ANY, "192.168.100.3", 80) ||
                        f.connectBetween("192.168.100.147", Flow.PORT_ANY, "192.168.100.3", 80)) {
                    return "DOS";
                } else return "NORMAL";
            });
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
        System.out.println(Utils.DividingLine);
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
