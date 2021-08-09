package io.tomahawkd.cic.execute;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.flow.Flow;
import io.tomahawkd.cic.flow.FlowGenerator;
import io.tomahawkd.cic.label.LabelStrategy;
import io.tomahawkd.cic.label.LabelStrategyFactoryManager;
import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.packet.PacketReader;
import io.tomahawkd.cic.source.LocalFile;
import io.tomahawkd.cic.source.LocalFiles;
import io.tomahawkd.cic.source.LocalMultiFile;
import io.tomahawkd.cic.source.LocalSingleFile;
import io.tomahawkd.cic.thread.PacketDispatcher;
import io.tomahawkd.cic.util.Utils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapClosedException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

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
        Map<LocalFile, Path> inputOutputPaths = delegate.getInputOutputPaths();
        boolean oneFile = delegate.isOneFile();
        Path oneOutputPath = delegate.getOneFilePath();
        ExecutionMode mode = delegate.getMode();
        int threads = delegate.getFlowThreadCount();

        if (oneFile) {
            initFile(oneOutputPath);
            inputOutputPaths.forEach((inputFile, ignored) -> {
                logger.info("Start Processing {}", inputFile.getFileName());
                readPcapFile(inputFile, oneOutputPath, flowTimeout, activityTimeout, mode, threads);
            });
        } else {
            inputOutputPaths.forEach((inputFile, outputPath) -> {
                initFile(outputPath);
                logger.info("Start Processing {}", inputFile.getFileName());
                readPcapFile(inputFile, outputPath, flowTimeout, activityTimeout, mode, threads);
            });
        }
    }

    private void readPcapFile(LocalFile inputFile, Path outputPath, long flowTimeout, long activityTimeout, ExecutionMode mode, int threads) {
        if (inputFile == null || outputPath == null) {
            logger.fatal("Got a null path.");
            throw new RuntimeException("Got a null path.");
        }

        if (!LocalFiles.exists(inputFile) || !Files.exists(outputPath)) {
            logger.fatal("File not found. Status: input({}), output({})",
                    LocalFiles.exists(inputFile), Files.exists(outputPath));
            throw new RuntimeException("File not found.");
        }

        String fileName = inputFile.getFileName();
        System.out.printf("Working on... %s%n", fileName);

        // setting up
        LabelStrategy strategy = LabelStrategyFactoryManager.get().getStrategy(inputFile);
        PacketDispatcher dispatcher = new PacketDispatcher(threads, () -> {
            FlowGenerator flowGen = new FlowGenerator(flowTimeout, activityTimeout, mode);
            flowGen.setFlowLabelSupplier(strategy);

            // data export
            flowGen.addFlowListener(flow -> Utils.insertToFile(flow.exportData(), outputPath));
            return flowGen;
        });

        dispatcher.start();
        if (inputFile instanceof LocalMultiFile) {
            LocalMultiFile file = (LocalMultiFile) inputFile;
            file.getSegments().forEach(localSingleFile -> readData(dispatcher, localSingleFile.getFilePath()));
        } else if (inputFile instanceof LocalSingleFile) {
            readData(dispatcher, inputFile.getFilePath());
        }

        dispatcher.stop();

        System.out.printf("%s is done. total %d flows %n", inputFile.getFileName(), dispatcher.getFlowCount());
        System.out.println(Utils.DividingLine);
    }

    private void readData(PacketDispatcher dispatcher, Path filePath) {
        PacketReader packetReader = new PacketReader(filePath.toString());
        long nTotal = 0;
        long nValid = 0;
        while (true) {
            try {
                PacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if (basicPacket != null) {
                    dispatcher.dispatch(basicPacket);
                    nValid++;
                }
                System.out.printf("%s -> %d packets, %d flows \r", filePath.getFileName(), nTotal, dispatcher.getFlowCount());
            } catch (PcapClosedException e) {
                break;
            }
        }

        System.out.printf("Packet stats: Total=%d,Valid=%d,Discarded=%d%n", nTotal, nValid, nTotal - nValid);
    }

    private void initFile(Path file) {
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
