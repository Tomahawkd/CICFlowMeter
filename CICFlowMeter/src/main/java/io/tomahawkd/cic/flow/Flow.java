package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.flow.features.*;
import io.tomahawkd.cic.label.LabelStrategy;
import io.tomahawkd.cic.packet.PacketInfo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Flow implements FlowFeature {

    // features
    private final List<FlowFeature> features;

    private Flow() {
        this.features = new ArrayList<>();
        features.add(new FlowBasicFeature(
                "", new byte[0], new byte[0], 0, 0, null, 0, null));
        FlowFeatureBuilder.INSTANCE.buildClasses(this);
    }

    public Flow(PacketInfo info, long flowActivityTimeOut, LabelStrategy supplier) {
        this.features = new ArrayList<>();
        features.add(new FlowBasicFeature(info.getFlowId(),
                info.getSrc(), info.getDst(),
                info.getSrcPort(), info.getDstPort(),
                supplier, flowActivityTimeOut, this));
        FlowFeatureBuilder.INSTANCE.buildClasses(this);
        addPacket(info);
    }

    public static String getHeaders() {
        Flow flow = new Flow();
        return flow.headers();
    }

    public void addFeature(FlowFeature feature) {
        features.add(feature);
    }

    @Override
    public String headers() {
        return features.stream().map(FlowFeature::headers).reduce("", (r, s) -> r + s) +
                FlowFeatureTag.Label.getName();
    }

    @Override
    public String exportData() {
        return features.stream().map(FlowFeature::exportData).reduce("", (r, s) -> r + s) +
                getBasicInfo().getLabelStrategy().getLabel(this);
    }

    @Override
    public int columnCount() {
        return features.stream().mapToInt(FlowFeature::columnCount).sum() + 1;
    }

    public void addPacket(PacketInfo info) {
        boolean fwd = Arrays.equals(this.getBasicInfo().src(), info.getSrc());
        addPacket(info, fwd);

        // update last to make sure that last seen is directing the previous packet (for FlowBasicFeature)
        postAddPacket(info);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        for (FlowFeature data : features) {
            data.addPacket(info, fwd);
        }
    }

    @Override
    public void postAddPacket(PacketInfo info) {
        for (FlowFeature data : features) {
            data.postAddPacket(info);
        }
    }

    @Override
    public void finalizeFlow() {
        for (FlowFeature data : features) {
            data.finalizeFlow();
        }
    }

    public long getFlowStartTime() {
        return getBasicInfo().getFlowStartTime();
    }

    public long getFlowLastSeen() {
        return getBasicInfo().getFlowLastSeen();
    }

    public String getFlowId() {
        return getBasicInfo().getFlowId();
    }

    public String getSrc() {
        return getBasicInfo().getSrc();
    }

    public String getDst() {
        return getBasicInfo().getDst();
    }

    public int getSrcPort() {
        return getBasicInfo().getSrcPort();
    }

    public int getDstPort() {
        return getBasicInfo().getDstPort();
    }

    public int getForwardFIN() {
        return getDep(TcpFlagFeature.class).getForwardFIN();
    }

    public int getBackwardFIN() {
        return getDep(TcpFlagFeature.class).getBackwardFIN();
    }

    public static final int PORT_ANY = -1;

    /**
     * set port to -1 to indicate ANY
     */
    public boolean connectBetween(String peer1, int port1, String peer2, int port2) {
        if (getSrc().equals(peer1) && (port1 == PORT_ANY || getSrcPort() == port1)) {
            return getDst().equals(peer2) && (port2 == PORT_ANY || getDstPort() == port2);
        }

        if (getDst().equals(peer1) && (port1 == PORT_ANY || getDstPort() == port1)) {
            return getSrc().equals(peer2) && (port2 == PORT_ANY || getSrcPort() == port2);
        }

        return false;
    }

    public final <T extends FlowFeature> T getDep(Class<T> depClass) {
        for (FlowFeature item: features) {
            if (item.getClass().equals(depClass)) return depClass.cast(item);
        }
        throw new IllegalArgumentException(depClass.getName() + " not found.");
    }

    public final FlowBasicFeature getBasicInfo() {
        return getDep(FlowBasicFeature.class);
    }
}
