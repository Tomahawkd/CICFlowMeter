package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.data.PacketInfo;
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
        FlowFeatureTag.subfl_fw_pkt,
        FlowFeatureTag.subfl_fw_byt,
        FlowFeatureTag.subfl_bw_pkt,
        FlowFeatureTag.subfl_bw_byt,
})
public class FlowActiveFeature extends AbstractFlowFeature {

    private long startActiveTime;
    private long endActiveTime;

    private final SummaryStatistics flowActive = new SummaryStatistics();
    private final SummaryStatistics flowIdle = new SummaryStatistics();

    private long sfLastPacketTS=-1;
    private int sfCount=0;
    private long sfAcHelper=-1;

    public FlowActiveFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        long timeout = getBasicInfo().getFlowActivityTimeOut();
        updateActiveIdleTime(info.getTimestamp(), timeout);
        detectUpdateSubflows(info, timeout);
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

    public double getSflow_fbytes(){
        if(sfCount <= 0) return 0;
        return getDep(PacketSizeFeature.class).getForwardPacketBytes()/sfCount;
    }

    public long getSflow_fpackets(){
        if(sfCount <= 0) return 0;
        return getDep(PacketSizeFeature.class).getForwardPacketCount()/sfCount;
    }

    public double getSflow_bbytes(){
        if(sfCount <= 0) return 0;
        return getDep(PacketSizeFeature.class).getBackwardPacketBytes()/sfCount;
    }
    public long getSflow_bpackets(){
        if(sfCount <= 0) return 0;
        return getDep(PacketSizeFeature.class).getBackwardPacketCount()/sfCount;
    }

    private void detectUpdateSubflows(PacketInfo packet, long timeout) {
        if(sfLastPacketTS == -1){
            sfLastPacketTS = packet.getTimestamp();
            sfAcHelper   = packet.getTimestamp();
        }

        if(((packet.getTimestamp() - sfLastPacketTS)/(double)1000000)  > 1.0){
            sfCount ++ ;
            long lastSFduration = packet.getTimestamp() - sfAcHelper;
            updateActiveIdleTime(packet.getTimestamp(), timeout);
            sfAcHelper = packet.getTimestamp();
        }
        sfLastPacketTS = packet.getTimestamp();
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        dataToString(flowActive, builder);
        dataToString(flowIdle, builder);
        builder.append(getSflow_fpackets()).append(SEPARATOR); // FlowFeatureTag.subfl_fw_pkt,
        builder.append(getSflow_fbytes()).append(SEPARATOR); // FlowFeatureTag.subfl_fw_byt,
        builder.append(getSflow_bpackets()).append(SEPARATOR); // FlowFeatureTag.subfl_bw_pkt,
        builder.append(getSflow_bbytes()).append(SEPARATOR); // FlowFeatureTag.subfl_bw_byt,
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
