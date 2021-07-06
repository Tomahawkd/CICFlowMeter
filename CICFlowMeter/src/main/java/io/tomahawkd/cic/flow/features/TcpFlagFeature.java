package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.data.PacketInfo;
import io.tomahawkd.cic.flow.Flow;

import java.util.Arrays;

@Feature(name = "TcpFlagFeature", tags = {
        FlowFeatureTag.fin_cnt,
        FlowFeatureTag.syn_cnt,
        FlowFeatureTag.rst_cnt,
        FlowFeatureTag.psh_cnt,
        FlowFeatureTag.ack_cnt,
        FlowFeatureTag.urg_cnt,
        FlowFeatureTag.cwr_cnt,
        FlowFeatureTag.ece_cnt,
        FlowFeatureTag.fw_psh_flag,
        FlowFeatureTag.bw_psh_flag,
        FlowFeatureTag.fw_urg_flag,
        FlowFeatureTag.bw_urg_flag
})
public class TcpFlagFeature extends AbstractFlowFeature {

    private static final int[] flagCounts = new int[10];

    public TcpFlagFeature(Flow flow) {
        super(null);
        Arrays.fill(flagCounts, 0);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        if (info.getFlag(PacketInfo.FLAG_FIN)) {
            flagCounts[FIN]++;
        }
        if (info.getFlag(PacketInfo.FLAG_SYN)) {
            flagCounts[SYN]++;
        }
        if (info.getFlag(PacketInfo.FLAG_RST)) {
            flagCounts[RST]++;
        }
        if (info.getFlag(PacketInfo.FLAG_PSH)) {
            if (fwd) flagCounts[FW_PSH]++;
            else flagCounts[BW_PSH]++;
        }
        if (info.getFlag(PacketInfo.FLAG_ACK)) {
            flagCounts[ACK]++;
        }
        if (info.getFlag(PacketInfo.FLAG_URG)) {
            if (fwd) flagCounts[FW_URG]++;
            else flagCounts[BW_URG]++;
        }
        if (info.getFlag(PacketInfo.FLAG_CWR)) {
            flagCounts[CWR]++;
        }
        if (info.getFlag(PacketInfo.FLAG_ECE)) {
            flagCounts[ECE]++;
        }
    }

    @Override
    public String exportData() {
        return flagCounts[FIN] + SEPARATOR + // fin_cnt
                flagCounts[SYN] + SEPARATOR + // syn_cnt
                flagCounts[RST] + SEPARATOR + // rst_cnt
                (flagCounts[FW_PSH] + flagCounts[BW_PSH]) + SEPARATOR + // psh_cnt
                flagCounts[ACK] + SEPARATOR + // ack_cnt
                (flagCounts[FW_URG] + flagCounts[BW_URG]) + SEPARATOR + // urg_cnt
                flagCounts[CWR] + SEPARATOR + // cwr_cnt
                flagCounts[ECE] + SEPARATOR + // ece_cnt
                flagCounts[FW_PSH] + SEPARATOR + // fw_psh_flag
                flagCounts[BW_PSH] + SEPARATOR + // bw_psh_flag
                flagCounts[FW_URG] + SEPARATOR + // fw_urg_flag
                flagCounts[BW_URG] + SEPARATOR;// bw_urg_flag
    }

    private static final int FIN = 0;
    private static final int SYN = 1;
    private static final int RST = 2;
    private static final int ACK = 3;
    private static final int CWR = 4;
    private static final int ECE = 5;
    private static final int FW_PSH = 6;
    private static final int BW_PSH = 7;
    private static final int FW_URG = 8;
    private static final int BW_URG = 9;
}
