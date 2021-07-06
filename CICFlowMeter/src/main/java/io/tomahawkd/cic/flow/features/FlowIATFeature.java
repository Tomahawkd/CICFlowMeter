package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.flow.Flow;
import org.apache.commons.math3.stat.descriptive.StatisticalSummary;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

import java.util.List;

@Feature(name = "FlowIATFeature", tags = {
        FlowFeatureTag.fl_iat_avg,
        FlowFeatureTag.fl_iat_std,
        FlowFeatureTag.fl_iat_max,
        FlowFeatureTag.fl_iat_min,
        FlowFeatureTag.fw_iat_tot,
        FlowFeatureTag.fw_iat_avg,
        FlowFeatureTag.fw_iat_std,
        FlowFeatureTag.fw_iat_max,
        FlowFeatureTag.fw_iat_min,
        FlowFeatureTag.bw_iat_tot,
        FlowFeatureTag.bw_iat_avg,
        FlowFeatureTag.bw_iat_std,
        FlowFeatureTag.bw_iat_max,
        FlowFeatureTag.bw_iat_min,
})
public class FlowIATFeature extends AbstractFlowFeature {

    private long forwardLastSeen = 0L;
    private long backwardLastSeen = 0L;

    private final SummaryStatistics flowIAT = new SummaryStatistics();
    private final SummaryStatistics forwardIAT = new SummaryStatistics();
    private final SummaryStatistics backwardIAT = new SummaryStatistics();

    public FlowIATFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        long currentTimestamp = info.getTimestamp();

        // not first packet
        if (currentTimestamp != 0L) {
            this.flowIAT.addValue(currentTimestamp - getBasicInfo().getFlowLastSeen());
            if (fwd) this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
            else this.backwardIAT.addValue(currentTimestamp - this.backwardLastSeen);
        }

        // finally update the last seen field
        if (fwd) forwardLastSeen = currentTimestamp;
        else backwardLastSeen = currentTimestamp;
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();

        if (flowIAT.getN() > 0) {
            builder.append(flowIAT.getMean()).append(SEPARATOR); // FlowFeature.fl_iat_avg
            builder.append(flowIAT.getStandardDeviation()).append(SEPARATOR); // FlowFeature.fl_iat_std
            builder.append(flowIAT.getMax()).append(SEPARATOR); // FlowFeature.fl_iat_max
            builder.append(flowIAT.getMean()).append(SEPARATOR); // FlowFeature.fl_iat_min

            subIATUpdate(builder, forwardIAT);
            subIATUpdate(builder, backwardIAT);
        } else {
            // if flowIAT don't have 2 packets for calculate, that means the forward/backward IAT don't have.
            return super.exportData(); // all 0
        }

        return builder.toString();
    }

    private void subIATUpdate(StringBuilder builder, StatisticalSummary subIat) {
        if (subIat.getN() > 0) {
            builder.append(subIat.getSum()).append(SEPARATOR); // FlowFeature.fbw_iat_tot
            builder.append(subIat.getMean()).append(SEPARATOR); // FlowFeature.fbw_iat_avg
            builder.append(subIat.getStandardDeviation()).append(SEPARATOR); // FlowFeature.fbw_iat_std
            builder.append(subIat.getMax()).append(SEPARATOR); // FlowFeature.fbw_iat_max
            builder.append(subIat.getMin()).append(SEPARATOR); // FlowFeature.fbw_iat_min
        } else {
            addZeroesToBuilder(builder, 5);
        }
    }
}
