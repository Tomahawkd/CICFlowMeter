package io.tomahawkd.cic;

import io.tomahawkd.cic.config.CommandlineDelegate;
import io.tomahawkd.cic.jnetpcap.*;
import io.tomahawkd.cic.jnetpcap.FlowGenListener;
import io.tomahawkd.config.ConfigManager;
import io.tomahawkd.config.commandline.CommandlineConfig;
import io.tomahawkd.config.commandline.CommandlineConfigSource;
import io.tomahawkd.config.sources.SourceManager;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jnetpcap.PcapClosedException;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

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
        long flowTimeout = delegate.getFlowTimeout();
        long activityTimeout = delegate.getActivityTimeout();
        List<Path> pcapPath = delegate.getPcapPath();
        Path outPath = delegate.getOutputPath();

        pcapPath.forEach(p -> {
            logger.info("Start Processing {}", p.getFileName().toString());
            readPcapFile(p, outPath, flowTimeout, activityTimeout);
        });
    }

    private static void readPcapFile(Path inputFile, Path outPath, long flowTimeout, long activityTimeout) {
        if (inputFile == null || outPath == null) {
            return;
        }

        String fileName = FilenameUtils.getName(inputFile.toString());
        File saveFileFullPath = outPath.resolve(fileName + Utils.FLOW_SUFFIX).toFile();
        if (saveFileFullPath.exists()) {
            if (!saveFileFullPath.delete()) {
                System.out.println("Save file can not be deleted");
            }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName, outPath.toString()));
        PacketReader packetReader = new PacketReader(inputFile.toString());

        System.out.printf("Working on... %s%n", fileName);

        int nValid = 0;
        int nTotal = 0;
        int nDiscarded = 0;
        long start = System.currentTimeMillis();
        int i = 0;
        while (true) {
            // i = (i)%animationChars.length;
            // System.out.print("Working on "+ inputFile+" "+ animationChars[i] +"\r");
            try {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                nTotal++;
                if (basicPacket != null) {
                    flowGen.addPacket(basicPacket);
                    nValid++;
                } else {
                    nDiscarded++;
                }
            } catch (PcapClosedException e) {
                break;
            }
            i++;
        }

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());

        long lines = Utils.countLines(saveFileFullPath.getPath());

        System.out.printf("%s is done. total %d flows %n", fileName, lines);
        System.out.printf("Packet stats: Total=%d,Valid=%d,Discarded=%d%n", nTotal, nValid, nDiscarded);
        System.out.println(DividingLine);

        //long end = System.currentTimeMillis();
        //logger.info(String.format("Done! in %d seconds",((end-start)/1000)));
        //logger.info(String.format("\t Total packets: %d",nTotal));
        //logger.info(String.format("\t Valid packets: %d",nValid));
        //logger.info(String.format("\t Ignored packets:%d %d ", nDiscarded,(nTotal-nValid)));
        //logger.info(String.format("PCAP duration %d seconds",((packetReader.getLastPacket()- packetReader.getFirstPacket())/1000)));
        //int singleTotal = flowGen.dumpLabeledFlowBasedFeatures(outPath, fileName+ FlowMgr.FLOW_SUFFIX, FlowFeature.getHeader());
        //logger.info(String.format("Number of Flows: %d",singleTotal));
        //logger.info("{} is done,Total {} flows",inputFile,singleTotal);
        //System.out.println(String.format("%s is done,Total %d flows", inputFile, singleTotal));
    }

    static class FlowListener implements FlowGenListener {

        private final String fileName;
        private final String outPath;

        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {
            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            Utils.insertToFile(FlowFeature.getHeader(), flowStringList, outPath, fileName + Utils.FLOW_SUFFIX);
            cnt++;
            String console = String.format("%s -> %d flows \r", fileName, cnt);
            System.out.print(console);
        }
    }
}
