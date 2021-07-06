package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.util.FlowGenListener;
import io.tomahawkd.cic.util.FlowLabelSupplier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.stream.Collectors;

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

    public void setFlowLabelSupplier(FlowLabelSupplier supplier) {
        flowLabelSupplier = supplier;
    }

    public void addPacket(PacketInfo packet) {
        if (packet == null) return;

        packetCounter++;
        if (packetCounter > 0x8000) {
            flushTimeoutFlows(packet.getTimestamp());
            packetCounter = 0;
        }

        String id;
        if (this.currentFlows.containsKey(packet.fwdFlowId())) {
            id = packet.setFwd().getFlowId();
        } else if (this.currentFlows.containsKey(packet.bwdFlowId())) {
            id = packet.setBwd().getFlowId();
        } else {
            currentFlows.put(packet.setFwd().getFlowId(), new Flow(packet, flowActivityTimeOut, flowLabelSupplier));
            return;
        }

        Flow flow = currentFlows.get(id);
        long currentTimestamp = packet.getTimestamp();

        // Flow finished due flowtimeout:
        // 1.- we move the flow to finished flow list
        // 2.- we eliminate the flow from the current flow list
        // 3.- we create a new flow with the packet-in-process
        if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut) {
            listeners.forEach(l -> l.onFlowGenerated(flow));
            currentFlows.remove(id);
            currentFlows.put(id, new Flow(packet, flow));

            // Flow finished due FIN flag (tcp only):
            // 1.- we add the packet-in-process to the flow (it is the last packet)
            // 2.- we move the flow to finished flow list
            // 3.- we eliminate the flow from the current flow list
        } else if (packet.getFlag(PacketInfo.FLAG_FIN)) {

            //
            // Forward Flow
            //
            if (Arrays.equals(flow.getBasicInfo().src(), packet.getSrc())) {
                if (flow.getForwardFIN() > 0) {
                    // some error
                    // TODO: review what to do with the packet
                    logger.warn("Received {} FIN flags in forward packets.", flow.getForwardFIN());
                    return; // DISCARDED for now
                } else {
                    if (flow.getBackwardFIN() > 0) {
                        finishFlow(flow, packet, id, "FlagFIN");
                        return;
                    }
                }
            } else {
                //
                // Backward Flow
                //
                if (flow.getBackwardFIN() > 0) {
                    // some error
                    // TODO: review what to do with the packet
                    logger.warn("Received {} FIN flags in backward packets.", flow.getBackwardFIN());
                    return; // DISCARDED for now
                } else {
                    if (flow.getForwardFIN() > 0) {
                        finishFlow(flow, packet, id, "FlagFIN");
                        return;
                    }
                }
            }

            // not finish yet (opposite side FIN flag not received)
            flow.addPacket(packet);
            currentFlows.put(id, flow);
        } else if(packet.getFlag(PacketInfo.FLAG_RST)) {
            finishFlow(flow, packet, id, "FlagRST");
        } else {
            // If the current flow has FIN, not to accept the packet
            if (Arrays.equals(flow.getBasicInfo().src(), packet.getSrc())) {
                if (flow.getForwardFIN() > 0) return;
            } else {
                if (flow.getBackwardFIN() > 0) return;
            }
            flow.addPacket(packet);
            currentFlows.put(id, flow);
        }
    }

    public void dumpLabeledCurrentFlow() {
        // treat the left flows as completed
        currentFlows.values().forEach(f -> listeners.forEach(l -> l.onFlowGenerated(f)));
    }

    private void flushTimeoutFlows(long timestamp) {
        List<Map.Entry<String, Flow>> list = currentFlows.entrySet().stream()
                .filter(e -> timestamp - e.getValue().getFlowStartTime() > this.flowTimeOut)
                .collect(Collectors.toList());

        list.forEach(e -> {
            listeners.forEach(l -> l.onFlowGenerated(e.getValue()));
            currentFlows.remove(e.getKey());
        });

        logger.debug("Timeout current has {} flow", currentFlows.size());
        packetCounter = 0;
    }

    private void finishFlow(Flow flow, PacketInfo packet, String id, String type) {
        logger.debug("{} current has {} flow", type, currentFlows.size());
        flow.addPacket(packet);
        listeners.forEach(l -> l.onFlowGenerated(flow));
        currentFlows.remove(id);
    }
}
