package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.flow.Flow;
import org.apache.commons.math3.stat.descriptive.StatisticalSummary;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;

@Feature(name = "PacketSizeFeature", tags = {
        FlowFeatureTag.pkt_len_max,
        FlowFeatureTag.pkt_len_min,
        FlowFeatureTag.pkt_len_avg,
        FlowFeatureTag.pkt_len_std,
        FlowFeatureTag.pkt_len_var,
        FlowFeatureTag.fw_pkt_len_max,
        FlowFeatureTag.fw_pkt_len_min,
        FlowFeatureTag.fw_pkt_len_avg,
        FlowFeatureTag.fw_pkt_len_std,
        FlowFeatureTag.fw_pkt_len_total,
        FlowFeatureTag.fw_pkt_count,
        FlowFeatureTag.fw_hdr_len,
        FlowFeatureTag.fw_hdr_min,
        FlowFeatureTag.bw_pkt_len_max,
        FlowFeatureTag.bw_pkt_len_min,
        FlowFeatureTag.bw_pkt_len_avg,
        FlowFeatureTag.bw_pkt_len_std,
        FlowFeatureTag.bw_pkt_len_total,
        FlowFeatureTag.bw_pkt_count,
        FlowFeatureTag.bw_hdr_len,
        FlowFeatureTag.down_up_ratio,
        FlowFeatureTag.fl_byt_s,
        FlowFeatureTag.fl_pkt_s,
        FlowFeatureTag.fw_pkt_s,
        FlowFeatureTag.bw_pkt_s,
        FlowFeatureTag.fw_win_byt,
        FlowFeatureTag.bw_win_byt,
        FlowFeatureTag.fw_act_pkt,
        FlowFeatureTag.pkt_size_avg,
        FlowFeatureTag.fw_seg_avg,
        FlowFeatureTag.bw_seg_avg,
})
public class PacketSizeFeature extends AbstractFlowFeature {

    private final SummaryStatistics flowPacketStats = new SummaryStatistics();
    private final SummaryStatistics flowHeaderStats = new SummaryStatistics();
    private final SummaryStatistics fwdPacketStats = new SummaryStatistics();
    private final SummaryStatistics bwdPacketStats = new SummaryStatistics();
    private final SummaryStatistics fwdHeaderStats = new SummaryStatistics();
    private final SummaryStatistics bwdHeaderStats = new SummaryStatistics();

    private long actualDataPacket_forward = 0L;

    private boolean first = true;
    private int initWinBytes_forward = 0;
    private int initWinBytes_backward = 0;

    public PacketSizeFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        flowPacketStats.addValue(info.getPayloadBytes());
        flowHeaderStats.addValue(info.getHeaderBytes());
        if (info.getPayloadBytes() > 0) {
            actualDataPacket_forward++;
        }

        if (fwd) {
            fwdPacketStats.addValue(info.getPayloadBytes());
            fwdHeaderStats.addValue(info.getHeaderBytes());
            if (first) {
                initWinBytes_forward = info.getTcpWindow();
                first = false;
            }
        } else {
            bwdPacketStats.addValue(info.getPayloadBytes());
            bwdHeaderStats.addValue(info.getHeaderBytes());
            if (first) {
                initWinBytes_backward = info.getTcpWindow();
                first = false;
            }
        }
    }

    public long packetCount() {
        return this.flowPacketStats.getN();
    }

    public double getAvgPacketSize() {
        if (this.packetCount() > 0) {
            return (flowPacketStats.getSum() / this.packetCount());
        }
        return 0;
    }

    public double fAvgSegmentSize() {
        if (fwdPacketStats.getN() != 0)
            return (this.fwdPacketStats.getSum() / (double) fwdPacketStats.getN());
        return 0;
    }

    public double bAvgSegmentSize() {
        if (this.bwdPacketStats.getN() != 0)
            return (this.bwdPacketStats.getSum() / (double) fwdPacketStats.getN());
        return 0;
    }

    @Override
    public String exportData() {
        StringBuilder builder = new StringBuilder();
        if (flowPacketStats.getN() > 0) {
            builder.append(flowPacketStats.getMax()).append(SEPARATOR); //                 FlowFeatureTag.pkt_len_max,
            builder.append(flowPacketStats.getMin()).append(SEPARATOR); //                 FlowFeatureTag.pkt_len_min,
            builder.append(flowPacketStats.getMean()).append(SEPARATOR); //                FlowFeatureTag.pkt_len_avg,
            builder.append(flowPacketStats.getStandardDeviation()).append(SEPARATOR); //   FlowFeatureTag.pkt_len_std,
            builder.append(flowPacketStats.getVariance()).append(SEPARATOR); //            FlowFeatureTag.pkt_len_var,
        }

        subPacketUpdate(builder, fwdPacketStats);
        builder.append(fwdHeaderStats.getSum()).append(SEPARATOR); //                FlowFeatureTag.fw_hdr_len,
        builder.append(fwdHeaderStats.getMin()).append(SEPARATOR); // fw_hdr_min
        subPacketUpdate(builder, bwdPacketStats);
        builder.append(bwdHeaderStats.getSum()).append(SEPARATOR); //                FlowFeatureTag.bw_hdr_len,

        if (fwdPacketStats.getN() > 0) {
            builder.append(bwdPacketStats.getN() / fwdPacketStats.getN()).append(SEPARATOR); // down_up_ratio,
        } else {
            addZeroesToBuilder(builder, 1);
        }

        if (getBasicInfo().getDuration() > 0) {
            builder.append(flowPacketStats.getSum() / getBasicInfo().getDuration() / 1000000L).append(SEPARATOR); // fl_byt_s,
            builder.append(flowPacketStats.getN() / getBasicInfo().getDuration() / 1000000L).append(SEPARATOR); //   fl_pkt_s,
            builder.append(fwdPacketStats.getN() / getBasicInfo().getDuration() / 1000000L).append(SEPARATOR); //  fw_pkt_s,
            builder.append(bwdPacketStats.getN() / getBasicInfo().getDuration() / 1000000L).append(SEPARATOR); //  bw_pkt_s,
        } else {
            addZeroesToBuilder(builder, 4);
        }

        builder.append(actualDataPacket_forward).append(SEPARATOR); // fw_act_pkt
        builder.append(initWinBytes_forward).append(SEPARATOR); // fw_win_byt
        builder.append(initWinBytes_backward).append(SEPARATOR); // bw_win_byt

        builder.append(getAvgPacketSize()).append(SEPARATOR); // FlowFeatureTag.pkt_size_avg,
        builder.append(fAvgSegmentSize()).append(SEPARATOR); // FlowFeatureTag.fw_seg_avg,
        builder.append(bAvgSegmentSize()).append(SEPARATOR); // FlowFeatureTag.bw_seg_avg,
        return builder.toString();
    }

    private void subPacketUpdate(StringBuilder builder, StatisticalSummary data) {
        if (data.getN() > 0) {
            builder.append(data.getMax()).append(SEPARATOR); //                FlowFeatureTag.fw_pkt_len_max,
            builder.append(data.getMin()).append(SEPARATOR); //                FlowFeatureTag.fw_pkt_len_min,
            builder.append(data.getMean()).append(SEPARATOR); //                FlowFeatureTag.fw_pkt_len_avg,
            builder.append(data.getStandardDeviation()).append(SEPARATOR); //   FlowFeatureTag.fw_pkt_len_std,
            builder.append(data.getSum()).append(SEPARATOR); //                FlowFeatureTag.fw_pkt_len_total,
            builder.append(data.getN()).append(SEPARATOR); //                FlowFeatureTag.fw_pkt_count,
        } else {
            addZeroesToBuilder(builder, 6);
        }
    }

    //getters
    public double getForwardPacketBytes() {
        return fwdPacketStats.getSum();
    }

    public long getForwardPacketCount() {
        return fwdPacketStats.getN();
    }

    public double getBackwardPacketBytes() {
        return bwdPacketStats.getSum();
    }

    public long getBackwardPacketCount() {
        return bwdPacketStats.getN();
    }

    public long getPacketCount() {
        return flowPacketStats.getN();
    }
}
