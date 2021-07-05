package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.util.FlowGenListener;
import io.tomahawkd.cic.util.FlowLabelSupplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.tomahawkd.cic.util.Utils.LINE_SEP;

public class FlowGenerator {
    public static final Logger logger = LogManager.getLogger(FlowGenerator.class);

    private final List<FlowGenListener> listeners;
    private FlowLabelSupplier flowLabelSupplier = f -> "No Label";
    private final HashMap<String, Flow> currentFlows;

    private final long flowTimeOut;
    private final long flowActivityTimeOut;

    private int packetCounter;

    public FlowGenerator(long flowTimeout, long activityTimeout) {
        super();
        this.flowTimeOut = flowTimeout;
        this.flowActivityTimeOut = activityTimeout;
        currentFlows = new HashMap<>();
        packetCounter = 0;
        listeners = new ArrayList<>();
    }

    public void addFlowListener(FlowGenListener listener) {
        listeners.add(listener);
    }

    public void addPacket(PacketInfo packet) {
        if (packet == null) return;
        if (packetCounter > 1024) flushTimeoutFlows(packet.getTimestamp());

        Flow flow;
        long currentTimestamp = packet.getTimestamp();
        String id;
        packetCounter++;

        if (this.currentFlows.containsKey(packet.fwdFlowId())) {
            id = packet.setFwd().getFlowId();
        } else if (this.currentFlows.containsKey(packet.bwdFlowId())) {
            id = packet.setBwd().getFlowId();
        } else {
            currentFlows.put(packet.setFwd().getFlowId(), new Flow(packet, flowActivityTimeOut, flowLabelSupplier));
            return;
        }

        flow = currentFlows.get(id);
        // Flow finished due flowtimeout:
        // 1.- we move the flow to finished flow list
        // 2.- we eliminate the flow from the current flow list
        // 3.- we create a new flow with the packet-in-process
        if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut) {
            listeners.forEach(l -> l.onFlowGenerated(flow));
            currentFlows.remove(id);
            currentFlows.put(id, new Flow(packet, flow));

            int cfsize = currentFlows.size();
            if (cfsize % 50 == 0) {
                logger.debug("Timeout current has {} flow", cfsize);
            }

            // Flow finished due FIN flag (tcp only):
            // 1.- we add the packet-in-process to the flow (it is the last packet)
            // 2.- we move the flow to finished flow list
            // 3.- we eliminate the flow from the current flow list
        } else if (packet.getFlag(PacketInfo.FLAG_FIN)) {
            logger.debug("FlagFIN current has {} flow", currentFlows.size());
            flow.addPacket(packet);
            listeners.forEach(l -> l.onFlowGenerated(flow));
            currentFlows.remove(id);
        } else {
            flow.addPacket(packet);
            currentFlows.put(id, flow);
        }
    }

    public void dumpLabeledCurrentFlow(Path fileFullPath) {
        File file = fileFullPath.toFile();
        FileOutputStream output = null;
        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            } else {
                if (file.createNewFile()) {
                    output = new FileOutputStream(file);
                    output.write((FlowFeatureTag.getHeader() + LINE_SEP).getBytes());
                } else {
                    throw new IOException("File cannot be created.");
                }
            }

            for (Flow flow : currentFlows.values()) {
                output.write((flow.exportData() + LINE_SEP).getBytes());
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

    private void flushTimeoutFlows(long timestamp) {
        List<Map.Entry<String, Flow>> list = currentFlows.entrySet().stream()
                .filter(e -> timestamp - e.getValue().getFlowStartTime() > this.flowTimeOut)
                .collect(Collectors.toList());

        list.forEach(e -> {
            String id = e.getKey();
            Flow flow = e.getValue();
            listeners.forEach(l -> l.onFlowGenerated(flow));
            currentFlows.remove(id);
            logger.debug("Timeout current has {} flow", currentFlows.size());
        });

        packetCounter = 0;
    }

    public void setFlowLabelSupplier(FlowLabelSupplier supplier) {
        flowLabelSupplier = supplier;
    }
}
