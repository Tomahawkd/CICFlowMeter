package io.tomahawkd.cic.flow.features;

import io.tomahawkd.cic.packet.PacketInfo;
import io.tomahawkd.cic.flow.Flow;

@Feature(name = "BulkFeature", tags = {
        FlowFeatureTag.fw_byt_blk_avg,
        FlowFeatureTag.fw_pkt_blk_avg,
        FlowFeatureTag.fw_blk_rate_avg,
        FlowFeatureTag.bw_byt_blk_avg,
        FlowFeatureTag.bw_pkt_blk_avg,
        FlowFeatureTag.bw_blk_rate_avg,
}, ordinal = 5, type = FeatureType.TCP)
public class BulkFeature extends AbstractFlowFeature {

    private final Bulk fwdBulk = new Bulk();
    private final Bulk bwdBulk = new Bulk();

    public BulkFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        if (info.getPayloadBytes() <= 0) return;
        if (fwd) fwdBulk.update(info.getTimestamp(), info.getPayloadBytes(), bwdBulk);
        else bwdBulk.update(info.getTimestamp(), info.getPayloadBytes(), fwdBulk);
    }

    @Override
    public String exportData() {
        return fAvgBytesPerBulk() + SEPARATOR + //   fw_byt_blk_avg,
                fAvgPacketsPerBulk() + SEPARATOR +//  fw_pkt_blk_avg,
                fAvgBulkRate() + SEPARATOR + //       fw_blk_rate_avg,
                bAvgBytesPerBulk() + SEPARATOR + //   bw_byt_blk_avg,
                bAvgPacketsPerBulk() + SEPARATOR + // bw_pkt_blk_avg,
                bAvgBulkRate() + SEPARATOR;
    }


    public long fbulkStateCount() {
        return fwdBulk.bulkStateCount;
    }

    public long fbulkSizeTotal() {
        return fwdBulk.bulkSizeTotal;
    }

    public long fbulkPacketCount() {
        return fwdBulk.bulkPacketCount;
    }

    public long fbulkDuration() {
        return fwdBulk.bulkDuration;
    }

    public double fbulkDurationInSecond() {
        return fbulkDuration() / (double) 1000000;
    }


    //Client average bytes per bulk
    public long fAvgBytesPerBulk() {
        if (this.fbulkStateCount() != 0)
            return (this.fbulkSizeTotal() / this.fbulkStateCount());
        return 0;
    }


    //Client average packets per bulk
    public long fAvgPacketsPerBulk() {
        if (this.fbulkStateCount() != 0)
            return (this.fbulkPacketCount() / this.fbulkStateCount());
        return 0;
    }


    //Client average bulk rate
    public long fAvgBulkRate() {
        if (this.fbulkDuration() != 0)
            return (long) (this.fbulkSizeTotal() / this.fbulkDurationInSecond());
        return 0;
    }


    //new features server
    public long bbulkPacketCount() {
        return bwdBulk.bulkPacketCount;
    }

    public long bbulkStateCount() {
        return bwdBulk.bulkStateCount;
    }

    public long bbulkSizeTotal() {
        return bwdBulk.bulkSizeTotal;
    }

    public long bbulkDuration() {
        return bwdBulk.bulkDuration;
    }

    public double bbulkDurationInSecond() {
        return bbulkDuration() / (double) 1000000;
    }

    //Server average bytes per bulk
    public long bAvgBytesPerBulk() {
        if (this.bbulkStateCount() != 0)
            return (this.bbulkSizeTotal() / this.bbulkStateCount());
        return 0;
    }

    //Server average packets per bulk
    public long bAvgPacketsPerBulk() {
        if (this.bbulkStateCount() != 0)
            return (this.bbulkPacketCount() / this.bbulkStateCount());
        return 0;
    }

    //Server average bulk rate
    public long bAvgBulkRate() {
        if (this.bbulkDuration() != 0)
            return (long) (this.bbulkSizeTotal() / this.bbulkDurationInSecond());
        return 0;
    }

    private static class Bulk {

        private long bulkDuration = 0;
        private long bulkPacketCount = 0;
        private long bulkSizeTotal = 0;
        private long bulkStateCount = 0;
        private long bulkPacketCountHelper = 0;
        private long bulkStartTimestamp = 0;
        private long bulkSizeHelper = 0;
        private long lastBulkTimestamp = 0;

        public void update(long packetTimestamp, long packetSize, Bulk otherBulk) {
            if (otherBulk.lastBulkTimestamp > bulkStartTimestamp) bulkStartTimestamp = 0;

            if (bulkStartTimestamp == 0) {
                bulkStartTimestamp = packetTimestamp;
                bulkPacketCountHelper = 1;
                bulkSizeHelper = packetSize;
                lastBulkTimestamp = packetTimestamp;
            } //possible bulk
            else {
                // Too much idle time?
                if (((packetTimestamp - lastBulkTimestamp) / (double) 1000000) > 1.0) {
                    bulkStartTimestamp = packetTimestamp;
                    lastBulkTimestamp = packetTimestamp;
                    bulkPacketCountHelper = 1;
                    bulkSizeHelper = packetSize;
                }// Add to bulk
                else {
                    bulkPacketCountHelper += 1;
                    bulkSizeHelper += packetSize;
                    //New bulk
                    if (bulkPacketCountHelper == 4) {
                        bulkStateCount += 1;
                        bulkPacketCount += bulkPacketCountHelper;
                        bulkSizeTotal += bulkSizeHelper;
                        bulkDuration += packetTimestamp - bulkStartTimestamp;
                    } //Continuation of existing bulk
                    else if (bulkPacketCountHelper > 4) {
                        bulkPacketCount += 1;
                        bulkSizeTotal += packetSize;
                        bulkDuration += packetTimestamp - lastBulkTimestamp;
                    }
                    lastBulkTimestamp = packetTimestamp;
                }
            }

        }
    }
}
