package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.flow.Flow;

@Feature(name = "SubFlowFeature", tags = {
        FlowFeatureTag.subfl_fw_pkt,
        FlowFeatureTag.subfl_fw_byt,
        FlowFeatureTag.subfl_bw_pkt,
        FlowFeatureTag.subfl_bw_byt,
}, ordinal = 6)
public class SubFlowFeature extends AbstractFlowFeature {

    private long sfLastPacketTS=-1;
    private int sfCount=0;
    private long sfAcHelper=-1;

    public SubFlowFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        detectUpdateSubflows(info);
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

    private void detectUpdateSubflows(PacketInfo packet) {
        if(sfLastPacketTS == -1){
            sfLastPacketTS = packet.getTimestamp();
            sfAcHelper   = packet.getTimestamp();
        }

        if(((packet.getTimestamp() - sfLastPacketTS)/(double)1000000)  > 1.0){
            sfCount ++ ;
            long lastSFduration = packet.getTimestamp() - sfAcHelper;
            sfAcHelper = packet.getTimestamp();
        }
        sfLastPacketTS = packet.getTimestamp();
    }

    @Override
    public String exportData() {
        return getSflow_fpackets() + SEPARATOR + // FlowFeatureTag.subfl_fw_pkt,
                getSflow_fbytes() + SEPARATOR + // FlowFeatureTag.subfl_fw_byt,
                getSflow_bpackets() + SEPARATOR + // FlowFeatureTag.subfl_bw_pkt,
                getSflow_bbytes() + SEPARATOR;
    }
}
