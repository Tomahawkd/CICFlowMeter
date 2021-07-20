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

    // almost copy from BasicFlow
    private long fbulkDuration = 0;
    private long fbulkPacketCount = 0;
    private long fbulkSizeTotal = 0;
    private long fbulkStateCount = 0;
    private long fbulkPacketCountHelper = 0;
    private long fbulkStartHelper = 0;
    private long fbulkSizeHelper = 0;
    private long flastBulkTS = 0;
    private long bbulkDuration = 0;
    private long bbulkPacketCount = 0;
    private long bbulkSizeTotal = 0;
    private long bbulkStateCount = 0;
    private long bbulkPacketCountHelper = 0;
    private long bbulkStartHelper = 0;
    private long bbulkSizeHelper = 0;
    private long blastBulkTS = 0;

    public BulkFeature(Flow flow) {
        super(flow);
    }

    @Override
    public void addPacket(PacketInfo info, boolean fwd) {
        if (fwd)  updateForwardBulk(info, blastBulkTS);
        else updateBackwardBulk(info, flastBulkTS);
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


    public void updateForwardBulk(PacketInfo packet, long tsOflastBulkInOther) {
        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > fbulkStartHelper) fbulkStartHelper = 0;
        if (size <= 0) return;

        packet.getPayloadPacket();

        if (fbulkStartHelper == 0) {
            fbulkStartHelper = packet.getTimestamp();
            fbulkPacketCountHelper = 1;
            fbulkSizeHelper = size;
            flastBulkTS = packet.getTimestamp();
        } //possible bulk
        else {
            // Too much idle time?
            if (((packet.getTimestamp() - flastBulkTS) / (double) 1000000) > 1.0) {
                fbulkStartHelper = packet.getTimestamp();
                flastBulkTS = packet.getTimestamp();
                fbulkPacketCountHelper = 1;
                fbulkSizeHelper = size;
            }// Add to bulk
            else {
                fbulkPacketCountHelper += 1;
                fbulkSizeHelper += size;
                //New bulk
                if (fbulkPacketCountHelper == 4) {
                    fbulkStateCount += 1;
                    fbulkPacketCount += fbulkPacketCountHelper;
                    fbulkSizeTotal += fbulkSizeHelper;
                    fbulkDuration += packet.getTimestamp() - fbulkStartHelper;
                } //Continuation of existing bulk
                else if (fbulkPacketCountHelper > 4) {
                    fbulkPacketCount += 1;
                    fbulkSizeTotal += size;
                    fbulkDuration += packet.getTimestamp() - flastBulkTS;
                }
                flastBulkTS = packet.getTimestamp();
            }
        }
    }

    public void updateBackwardBulk(PacketInfo packet, long tsOflastBulkInOther) {
        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > bbulkStartHelper) bbulkStartHelper = 0;
        if (size <= 0) return;

        packet.getPayloadPacket();

        if (bbulkStartHelper == 0) {
            bbulkStartHelper = packet.getTimestamp();
            bbulkPacketCountHelper = 1;
            bbulkSizeHelper = size;
            blastBulkTS = packet.getTimestamp();
        } //possible bulk
        else {
            // Too much idle time?
            if (((packet.getTimestamp() - blastBulkTS) / (double) 1000000) > 1.0) {
                bbulkStartHelper = packet.getTimestamp();
                blastBulkTS = packet.getTimestamp();
                bbulkPacketCountHelper = 1;
                bbulkSizeHelper = size;
            }// Add to bulk
            else {
                bbulkPacketCountHelper += 1;
                bbulkSizeHelper += size;
                //New bulk
                if (bbulkPacketCountHelper == 4) {
                    bbulkStateCount += 1;
                    bbulkPacketCount += bbulkPacketCountHelper;
                    bbulkSizeTotal += bbulkSizeHelper;
                    bbulkDuration += packet.getTimestamp() - bbulkStartHelper;
                } //Continuation of existing bulk
                else if (bbulkPacketCountHelper > 4) {
                    bbulkPacketCount += 1;
                    bbulkSizeTotal += size;
                    bbulkDuration += packet.getTimestamp() - blastBulkTS;
                }
                blastBulkTS = packet.getTimestamp();
            }
        }

    }

    public long fbulkStateCount() {
        return fbulkStateCount;
    }

    public long fbulkSizeTotal() {
        return fbulkSizeTotal;
    }

    public long fbulkPacketCount() {
        return fbulkPacketCount;
    }

    public long fbulkDuration() {
        return fbulkDuration;
    }

    public double fbulkDurationInSecond() {
        return fbulkDuration / (double) 1000000;
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
        return bbulkPacketCount;
    }

    public long bbulkStateCount() {
        return bbulkStateCount;
    }

    public long bbulkSizeTotal() {
        return bbulkSizeTotal;
    }

    public long bbulkDuration() {
        return bbulkDuration;
    }

    public double bbulkDurationInSecond() {
        return bbulkDuration / (double) 1000000;
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
}
