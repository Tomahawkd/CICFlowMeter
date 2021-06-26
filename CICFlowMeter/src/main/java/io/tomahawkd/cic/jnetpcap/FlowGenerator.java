package io.tomahawkd.cic.jnetpcap;

import io.tomahawkd.cic.data.PackageInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.tomahawkd.cic.jnetpcap.Utils.LINE_SEP;

public class FlowGenerator {
    public static final Logger logger = LogManager.getLogger(FlowGenerator.class);

    private FlowGenListener mListener;
    private HashMap<String, BasicFlow> currentFlows;
    private HashMap<Integer, BasicFlow> finishedFlows;

    private final boolean bidirectional;
    private final long flowTimeOut;
    private final long flowActivityTimeOut;
    private int finishedFlowCount;

    public FlowGenerator(boolean bidirectional, long flowTimeout, long activityTimeout) {
        super();
        this.bidirectional = bidirectional;
        this.flowTimeOut = flowTimeout;
        this.flowActivityTimeOut = activityTimeout;
        init();
    }

    private void init() {
        currentFlows = new HashMap<>();
        finishedFlows = new HashMap<>();
        finishedFlowCount = 0;
    }

    public void setFlowListener(FlowGenListener listener) {
        mListener = listener;
    }

    public void addPacket(PackageInfo packet) {
        if (packet == null) {
            return;
        }

        BasicFlow flow;
        long currentTimestamp = packet.getTimestamp();
        String id;

        if (this.currentFlows.containsKey(packet.fwdFlowId())) {
            id = packet.setFwd().fwdFlowId();
        } else if (this.currentFlows.containsKey(packet.bwdFlowId())) {
            id = packet.setBwd().bwdFlowId();
        } else {
            currentFlows.put(packet.setFwd().fwdFlowId(), new BasicFlow(bidirectional, packet));
            return;
        }

        flow = currentFlows.get(id);
        // Flow finished due flowtimeout:
        // 1.- we move the flow to finished flow list
        // 2.- we eliminate the flow from the current flow list
        // 3.- we create a new flow with the packet-in-process
        if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut) {
            if (flow.packetCount() > 1) {
                listenerCallback(flow);
            }
            currentFlows.remove(id);
            currentFlows.put(id, new BasicFlow(bidirectional, packet, flow));

            int cfsize = currentFlows.size();
            if (cfsize % 50 == 0) {
                logger.debug("Timeout current has {} flow", cfsize);
            }

            // Flow finished due FIN flag (tcp only):
            // 1.- we add the packet-in-process to the flow (it is the last packet)
            // 2.- we move the flow to finished flow list
            // 3.- we eliminate the flow from the current flow list
        } else if (packet.getFlag(PackageInfo.FLAG_FIN)) {
            logger.debug("FlagFIN current has {} flow", currentFlows.size());
            flow.addPacket(packet);
            listenerCallback(flow);
            currentFlows.remove(id);
        } else {
            flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
            flow.addPacket(packet);
            currentFlows.put(id, flow);
        }
    }

    public void dumpLabeledCurrentFlow(String fileFullPath) {
        if (fileFullPath == null) {
            String ex = String.format("fullFilePath=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            } else {
                if (file.createNewFile()) {
                    output = new FileOutputStream(file);
                    output.write((FlowFeature.getHeader() + LINE_SEP).getBytes());
                } else {
                    throw new IOException("File cannot be created.");
                }
            }

            if (mListener == null) {
                for (BasicFlow flow : finishedFlows.values()) {
                    if (flow.packetCount() > 1) {
                        output.write((flow.dumpFlowBasedFeaturesEx() + LINE_SEP).getBytes());
                    } else {
                        logger.warn("Flow " + flow.getFlowId() + " is discarded since there is only one package.");
                    }
                }
            }

            for (BasicFlow flow : currentFlows.values()) {
                if (flow.packetCount() > 1) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + LINE_SEP).getBytes());
                } else {
                    logger.warn("Flow " + flow.getFlowId() + " is discarded since there is only one package.");
                }
            }

        } catch (IOException e) {
            logger.warn(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
    }

    public void flushTimeoutFlows(PackageInfo packet) {
        List<Map.Entry<String, BasicFlow>> list = currentFlows.entrySet().stream()
                .filter(e -> packet.getTimestamp() - e.getValue().getFlowStartTime() > this.flowTimeOut)
                .filter(e -> e.getValue().packetCount() > 1)
                .collect(Collectors.toList());

        list.forEach(e -> {
            String id = e.getKey();
            BasicFlow flow = e.getValue();
            listenerCallback(flow);
            currentFlows.remove(id);

            int cfsize = currentFlows.size();
            if (cfsize % 50 == 0) {
                logger.debug("Timeout current has {} flow", cfsize);
            }

        });
    }

    private void listenerCallback(BasicFlow flow) {
        if (mListener != null) {
            mListener.onFlowGenerated(flow);
        } else {
            finishedFlows.put(getFlowCount(), flow);
        }
    }

    private int getFlowCount() {
        this.finishedFlowCount++;
        return this.finishedFlowCount;
    }
}
