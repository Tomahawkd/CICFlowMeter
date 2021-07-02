package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.util.FlowLabelSupplier;
import org.jnetpcap.packet.format.FormatUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Flow implements FlowFeature {

    // features
    private final FlowBasicFeature basicInfo;
    private final List<FlowFeature> features;

    private Flow(FlowBasicFeature basicInfo) {
        this.basicInfo = basicInfo;
        this.features = new ArrayList<>();
        features.add(new PacketSizeFeature(basicInfo));
        features.add(new TcpFlagFeature());
        features.add(new FlowIATFeature(basicInfo));
        features.add(new FlowActiveFeature(basicInfo));
        features.add(new BulkFeature(basicInfo));
    }

    public Flow(PacketInfo info, Flow flow) {
        this(flow.basicInfo);
        this.basicInfo.reset();
        addPacket(info);
    }

    public Flow(PacketInfo info, long flowActivityTimeOut, FlowLabelSupplier supplier) {
        this(new FlowBasicFeature(info.getFlowId(),
                info.getSrc(), info.getDst(),
                info.getSrcPort(), info.getDstPort(),
                supplier, flowActivityTimeOut));
        addPacket(info);
    }

    @Override
    public String headers() {
        return basicInfo.headers() +
                features.stream().map(FlowFeature::headers).reduce("", (r, s) -> r + s) +
                FlowFeatureTag.Label.getName();
    }

    @Override
    public String exportData() {
        return basicInfo.exportData() +
                features.stream().map(FlowFeature::exportData).reduce("", (r, s) -> r + s) +
                basicInfo.getSupplier().get(this);
    }

    @Override
    public int columnCount() {
        return basicInfo.columnCount() +
                features.stream().mapToInt(FlowFeature::columnCount).sum() + 1;
    }

    public void addPacket(PacketInfo info) {
        boolean fwd = Arrays.equals(this.basicInfo.src(), info.getSrc());
        addPacket(info, fwd);

        // update last to make sure that last seen is directing the previous packet
        basicInfo.addPacket(info, fwd);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        for (FlowFeature data : features) {
            data.addPacket(info, fwd);
        }
    }

    public long getFlowStartTime() {
        return basicInfo.getFlowStartTime();
    }

    public String getFlowId() {
        return basicInfo.getFlowId();
    }

    public String getSrc() {
        return FormatUtils.ip(basicInfo.src());
    }

    public String getDst() {
        return FormatUtils.ip(basicInfo.dst());
    }

    public int getSrcPort() {
        return basicInfo.getSrcPort();
    }

    public int getDstPort() {
        return basicInfo.getDstPort();
    }
}
