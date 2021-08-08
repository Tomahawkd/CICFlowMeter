package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.execute.ExecutionMode;
import io.tomahawkd.cic.label.LabelStrategy;
import io.tomahawkd.cic.packet.PacketInfo;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.function.BiFunction;
import java.util.stream.Collectors;

public class FlowGenerator {
    public static final Logger logger = LogManager.getLogger(FlowGenerator.class);

    private final List<FlowGenListener> listeners;
    private LabelStrategy labelStrategy = f -> "No Label";
    private final HashMap<String, Flow> currentFlows;

    private final long flowTimeOut;
    private final long flowActivityTimeOut;

    private int packetCounter;

    private final BiFunction<Flow, Long, Boolean> timeoutStrategy;

    private long flowCount = 0;

    public FlowGenerator(long flowTimeout, long activityTimeout, ExecutionMode mode) {
        super();
        this.flowTimeOut = flowTimeout;
        this.flowActivityTimeOut = activityTimeout;
        currentFlows = new HashMap<>();
        packetCounter = 0;
        listeners = new ArrayList<>();

        if (mode == ExecutionMode.FULL || mode == ExecutionMode.ONLINE) {
            this.timeoutStrategy = this::fullTimeout;
        } else {
            this.timeoutStrategy = this::samplingTimeout;
        }
    }

    public void addFlowListener(FlowGenListener listener) {
        listeners.add(listener);
    }

    public void setFlowLabelSupplier(LabelStrategy supplier) {
        labelStrategy = supplier;
    }

    public long getFlowCount() {
        return flowCount;
    }

    public void addPacket(PacketInfo packet) {
        if (packet == null) return;

        logger.debug("Received packet with id {}", packet.getFlowId());
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
            currentFlows.put(packet.setFwd().getFlowId(), new Flow(packet, flowActivityTimeOut, labelStrategy));
            return;
        }

        Flow flow = currentFlows.get(id);

        // Flow finished due flowtimeout:
        // 1.- we move the flow to finished flow list
        // 2.- we eliminate the flow from the current flow list
        // 3.- we create a new flow with the packet-in-process
        // The function is moved to flush timeout, but NO NEW flow is created
        // However, if we flush the current flow, the flow-id is removed,
        // when we meet the packet with same flow-id, the flow is recreated, so it is equivalent


        // Flow finished due FIN flag (tcp only):
        // 1.- we add the packet-in-process to the flow (it is the last packet)
        // 2.- we move the flow to finished flow list
        // 3.- we eliminate the flow from the current flow list
        if (packet.getFlag(PacketInfo.FLAG_FIN)) {

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
        currentFlows.values().forEach(this::callback);
    }

    private void flushTimeoutFlows(long timestamp) {
        logger.debug("Flushing timeout flows.");
        List<Map.Entry<String, Flow>> list = currentFlows.entrySet().stream()
                .filter(e -> timeoutStrategy.apply(e.getValue(), timestamp))
                .collect(Collectors.toList());

        list.forEach(e -> {
            callback(e.getValue());
            currentFlows.remove(e.getKey());
        });

        logger.debug("Timeout current has {} flow", currentFlows.size());
    }

    private boolean samplingTimeout(Flow flow, long timestamp) {
        return timestamp - flow.getFlowStartTime() > this.flowTimeOut;
    }

    private boolean fullTimeout(Flow flow, long timestamp) {
        return timestamp - flow.getFlowLastSeen() > this.flowTimeOut;
    }

    private void finishFlow(Flow flow, PacketInfo packet, String id, String type) {
        logger.debug("{} current has {} flow", type, currentFlows.size());
        flow.addPacket(packet);
        flow.finalizeFlow();
        callback(flow);
        currentFlows.remove(id);
    }

    private void callback(Flow flow) {
        if (flow.getBasicInfo().hasHttp()) {
            flowCount++;
            listeners.forEach(l -> l.onFlowGenerated(flow));
        } else {
            logger.debug("Discarding flow {} which has no HTTP packets", flow);
        }
    }
}
