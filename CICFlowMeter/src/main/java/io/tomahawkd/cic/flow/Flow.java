package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.flow.features.*;
import io.tomahawkd.cic.util.FlowLabelSupplier;
import org.jnetpcap.packet.format.FormatUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Flow implements FlowFeature {

    // features
    private final List<FlowFeature> features;

    private Flow(FlowBasicFeature basicInfo) {
        basicInfo.reset();
        this.features = new ArrayList<>();
        features.add(basicInfo);
        FlowFeatureBuilder.INSTANCE.buildClasses(this);
    }

    public Flow(PacketInfo info, Flow flow) {
        this(flow.getBasicInfo());
        addPacket(info);
    }

    public Flow(PacketInfo info, long flowActivityTimeOut, FlowLabelSupplier supplier) {
        this(new FlowBasicFeature(info.getFlowId(),
                info.getSrc(), info.getDst(),
                info.getSrcPort(), info.getDstPort(),
                supplier, flowActivityTimeOut));
        addPacket(info);
    }

    public static String getHeaders() {
        Flow flow = new Flow(new FlowBasicFeature(
                "", new byte[0], new byte[0], 0, 0, null, 0));
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
                getBasicInfo().getSupplier().get(this);
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

    public long getFlowStartTime() {
        return getBasicInfo().getFlowStartTime();
    }

    public String getFlowId() {
        return getBasicInfo().getFlowId();
    }

    public String getSrc() {
        return FormatUtils.ip(getBasicInfo().src());
    }

    public String getDst() {
        return FormatUtils.ip(getBasicInfo().dst());
    }

    public int getSrcPort() {
        return getBasicInfo().getSrcPort();
    }

    public int getDstPort() {
        return getBasicInfo().getDstPort();
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
