package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.flow.Flow;
import org.apache.commons.math3.stat.descriptive.StatisticalSummary;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

@Feature(name = "FlowActiveFeature", tags = {
        FlowFeatureTag.atv_avg,
        FlowFeatureTag.atv_std,
        FlowFeatureTag.atv_max,
        FlowFeatureTag.atv_min,
        FlowFeatureTag.idl_avg,
        FlowFeatureTag.idl_std,
        FlowFeatureTag.idl_max,
        FlowFeatureTag.idl_min,
})
public class FlowActiveFeature extends AbstractFlowFeature {

    private long startActiveTime;
    private long endActiveTime;

    private final SummaryStatistics flowActive = new SummaryStatistics();
    private final SummaryStatistics flowIdle = new SummaryStatistics();

    public FlowActiveFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        updateActiveIdleTime(info.getTimestamp(), getBasicInfo().getFlowActivityTimeOut());
    }

    public void updateActiveIdleTime(long currentTime, long threshold){
        if ((currentTime - this.endActiveTime) > threshold){
            if((this.endActiveTime - this.startActiveTime) > 0){
                this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
            }
            this.flowIdle.addValue(currentTime - this.endActiveTime);
            this.startActiveTime = currentTime;
            this.endActiveTime = currentTime;
        }else{
            this.endActiveTime = currentTime;
        }
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        dataToString(flowActive, builder);
        dataToString(flowIdle, builder);
        return builder.toString();
    }

    public void dataToString(StatisticalSummary data, StringBuilder builder) {
        if (data.getN() > 0) {
            builder.append(data.getMean()).append(SEPARATOR); // FlowFeatureTag.idl_avg,
            builder.append(data.getStandardDeviation()).append(SEPARATOR); // FlowFeatureTag.idl_std,
            builder.append(data.getMax()).append(SEPARATOR); // FlowFeatureTag.idl_max,
            builder.append(data.getMin()).append(SEPARATOR); // FlowFeatureTag.idl_min,
        } else {
            addZeroesToBuilder(builder, 4);
        }
    }
}
