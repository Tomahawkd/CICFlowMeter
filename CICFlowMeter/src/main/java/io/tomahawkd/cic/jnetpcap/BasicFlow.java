package io.tomahawkd.cic.jnetpcap;

import io.tomahawkd.cic.data.PackageInfo;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;

import java.util.*;

public class BasicFlow {

    private final static String SEPARATOR = ",";

    // flow basic identifier
    private String flowId = null;
    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private int protocol;

    private final FlowLabelSupplier labelSupplier;

    private final boolean isBidirectional;

    private final List<PackageInfo> forward = new ArrayList<>();
    private final List<PackageInfo> backward = new ArrayList<>();

    private long forwardBytes = 0L;
    private long backwardBytes = 0L;
    private long fHeaderBytes = 0L;
    private long bHeaderBytes = 0L;

    private final Map<String, MutableInt> flagCounts = new HashMap<>();

    private int fPSH_cnt = 0;
    private int bPSH_cnt = 0;
    private int fURG_cnt = 0;
    private int bURG_cnt = 0;

    private long Act_data_pkt_forward = 0L;
    private long min_seg_size_forward = 0L;
    private int Init_Win_bytes_forward = 0;
    private int Init_Win_bytes_backward = 0;

    private long flowStartTime = 0L;
    private long startActiveTime = 0L;
    private long endActiveTime = 0L;

    private final SummaryStatistics fwdPktStats = new SummaryStatistics();
    private final SummaryStatistics bwdPktStats = new SummaryStatistics();
    private final SummaryStatistics flowIAT = new SummaryStatistics();
    private final SummaryStatistics forwardIAT = new SummaryStatistics();
    private final SummaryStatistics backwardIAT = new SummaryStatistics();
    private final SummaryStatistics flowLengthStats = new SummaryStatistics();
    private final SummaryStatistics flowActive = new SummaryStatistics();
    private final SummaryStatistics flowIdle = new SummaryStatistics();

    private long flowLastSeen = 0L;
    private long forwardLastSeen = 0L;
    private long backwardLastSeen = 0L;

    public BasicFlow(boolean isBidirectional, PackageInfo packet, byte[] flowSrc, byte[] flowDst, int flowSrcPort, int flowDstPort, FlowLabelSupplier supplier) {
        this(isBidirectional, packet, supplier);
        this.src = flowSrc;
        this.dst = flowDst;
        this.srcPort = flowSrcPort;
        this.dstPort = flowDstPort;
    }

    public BasicFlow(boolean isBidirectional, PackageInfo packet, FlowLabelSupplier supplier) {
        this.initFlags();
        this.isBidirectional = isBidirectional;
        this.firstPacket(packet);
        this.labelSupplier = supplier;
    }

    public BasicFlow(boolean isBidirectional, PackageInfo packet, BasicFlow flow) {
        this(isBidirectional, packet,
                Arrays.copyOf(flow.src, flow.src.length),
                Arrays.copyOf(flow.dst, flow.dst.length),
                flow.srcPort, flow.dstPort,
                flow.labelSupplier);
    }

    public void initFlags() {
        flagCounts.put("FIN", new MutableInt());
        flagCounts.put("SYN", new MutableInt());
        flagCounts.put("RST", new MutableInt());
        flagCounts.put("PSH", new MutableInt());
        flagCounts.put("ACK", new MutableInt());
        flagCounts.put("URG", new MutableInt());
        flagCounts.put("CWR", new MutableInt());
        flagCounts.put("ECE", new MutableInt());
    }

    public void firstPacket(PackageInfo packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        this.flowStartTime = packet.getTimestamp();
        this.flowLastSeen = packet.getTimestamp();
        this.startActiveTime = packet.getTimestamp();
        this.endActiveTime = packet.getTimestamp();
        this.flowLengthStats.addValue((double) packet.getPayloadBytes());

        if (this.src == null) {
            this.src = packet.getSrc();
            this.srcPort = packet.getSrcPort();
        }
        if (this.dst == null) {
            this.dst = packet.getDst();
            this.dstPort = packet.getDstPort();
        }
        if (Arrays.equals(this.src, packet.getSrc())) {
            this.min_seg_size_forward = packet.getHeaderBytes();
            Init_Win_bytes_forward = packet.getTcpWindow();
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());
            this.fwdPktStats.addValue((double) packet.getPayloadBytes());
            this.fHeaderBytes = packet.getHeaderBytes();
            this.forwardLastSeen = packet.getTimestamp();
            this.forwardBytes += packet.getPayloadBytes();
            this.forward.add(packet);
            if (packet.getFlag(PackageInfo.FLAG_PSH)) {
                this.fPSH_cnt++;
            }
            if (packet.getFlag(PackageInfo.FLAG_URG)) {
                this.fURG_cnt++;
            }
        } else {
            Init_Win_bytes_backward = packet.getTcpWindow();
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());
            this.bwdPktStats.addValue((double) packet.getPayloadBytes());
            this.bHeaderBytes = packet.getHeaderBytes();
            this.backwardLastSeen = packet.getTimestamp();
            this.backwardBytes += packet.getPayloadBytes();
            this.backward.add(packet);
            if (packet.getFlag(PackageInfo.FLAG_PSH)) {
                this.bPSH_cnt++;
            }
            if (packet.getFlag(PackageInfo.FLAG_URG)) {
                this.bURG_cnt++;
            }
        }
        this.protocol = packet.getProtocol();
        this.flowId = packet.getFlowId();
    }

    public void addPacket(PackageInfo packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        long currentTimestamp = packet.getTimestamp();
        if (isBidirectional) {
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());

            if (Arrays.equals(this.src, packet.getSrc())) {
                if (packet.getPayloadBytes() >= 1) {
                    this.Act_data_pkt_forward++;
                }
                this.fwdPktStats.addValue((double) packet.getPayloadBytes());
                this.fHeaderBytes += packet.getHeaderBytes();
                this.forward.add(packet);
                this.forwardBytes += packet.getPayloadBytes();
                if (this.forward.size() > 1)
                    this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
                this.forwardLastSeen = currentTimestamp;
                this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);

            } else {
                this.bwdPktStats.addValue((double) packet.getPayloadBytes());
                Init_Win_bytes_backward = packet.getTcpWindow();
                this.bHeaderBytes += packet.getHeaderBytes();
                this.backward.add(packet);
                this.backwardBytes += packet.getPayloadBytes();
                if (this.backward.size() > 1)
                    this.backwardIAT.addValue(currentTimestamp - this.backwardLastSeen);
                this.backwardLastSeen = currentTimestamp;
            }
        } else {
            if (packet.getPayloadBytes() >= 1) {
                this.Act_data_pkt_forward++;
            }
            this.fwdPktStats.addValue((double) packet.getPayloadBytes());
            this.flowLengthStats.addValue((double) packet.getPayloadBytes());
            this.fHeaderBytes += packet.getHeaderBytes();
            this.forward.add(packet);
            this.forwardBytes += packet.getPayloadBytes();
            this.forwardIAT.addValue(currentTimestamp - this.forwardLastSeen);
            this.forwardLastSeen = currentTimestamp;
            this.min_seg_size_forward = Math.min(packet.getHeaderBytes(), this.min_seg_size_forward);
        }

        this.flowIAT.addValue(packet.getTimestamp() - this.flowLastSeen);
        this.flowLastSeen = packet.getTimestamp();

    }

    public String getSrc() {
        return FormatUtils.ip(src);
    }

    public String getDst() {
        return FormatUtils.ip(dst);
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public double getfPktsPerSecond() {
        long duration = this.flowLastSeen - this.flowStartTime;
        if (duration > 0) {
            return (this.forward.size() / ((double) duration / 1000000L));
        } else
            return 0;
    }

    public double getbPktsPerSecond() {
        long duration = this.flowLastSeen - this.flowStartTime;
        if (duration > 0) {
            return (this.backward.size() / ((double) duration / 1000000L));
        } else
            return 0;
    }

    public double getDownUpRatio() {
        if (this.forward.size() > 0) {
            return ((double) (this.backward.size()) / this.forward.size());
        }
        return 0;
    }

    public double getAvgPacketSize() {
        if (this.packetCount() > 0) {
            return (this.flowLengthStats.getSum() / this.packetCount());
        }
        return 0;
    }

    public double fAvgSegmentSize() {
        if (this.forward.size() != 0)
            return (this.fwdPktStats.getSum() / (double) this.forward.size());
        return 0;
    }

    public double bAvgSegmentSize() {
        if (this.backward.size() != 0)
            return (this.bwdPktStats.getSum() / (double) this.backward.size());
        return 0;
    }

    public void checkFlags(PackageInfo packet) {
        if (packet.getFlag(PackageInfo.FLAG_FIN)) {
            flagCounts.get("FIN").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_SYN)) {
            flagCounts.get("SYN").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_RST)) {
            flagCounts.get("RST").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_PSH)) {
            flagCounts.get("PSH").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_ACK)) {
            flagCounts.get("ACK").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_URG)) {
            flagCounts.get("URG").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_CWR)) {
            flagCounts.get("CWR").increment();
        }
        if (packet.getFlag(PackageInfo.FLAG_ECE)) {
            flagCounts.get("ECE").increment();
        }
    }

    public long getSflow_fbytes() {
        if (sfCount <= 0) return 0;
        return this.forwardBytes / sfCount;
    }

    public long getSflow_fpackets() {
        if (sfCount <= 0) return 0;
        return this.forward.size() / sfCount;
    }

    public long getSflow_bbytes() {
        if (sfCount <= 0) return 0;
        return this.backwardBytes / sfCount;
    }

    public long getSflow_bpackets() {
        if (sfCount <= 0) return 0;
        return this.backward.size() / sfCount;
    }

    private long sfLastPacketTS = -1;
    private int sfCount = 0;
    private long sfAcHelper = -1;

    void detectUpdateSubflows(PackageInfo packet) {
        if (sfLastPacketTS == -1) {
            sfLastPacketTS = packet.getTimestamp();
            sfAcHelper = packet.getTimestamp();
        }
        //System.out.print(" - "+(packet.timeStamp - sfLastPacketTS));
        if ((packet.getTimestamp() - (sfLastPacketTS) / (double) 1000000) > 1.0) {
            sfCount++;
            long lastSFduration = packet.getTimestamp() - sfAcHelper;
            updateActiveIdleTime(packet.getTimestamp() - sfLastPacketTS, 5000000L);
            sfAcHelper = packet.getTimestamp();
        }
        sfLastPacketTS = packet.getTimestamp();
    }

    //////////////////////////////
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


    public void updateFlowBulk(PackageInfo packet) {
        if (this.src == packet.getSrc()) {
            updateForwardBulk(packet, blastBulkTS);
        } else {
            updateBackwardBulk(packet, flastBulkTS);
        }
    }

    public void updateForwardBulk(PackageInfo packet, long tsOflastBulkInOther) {
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

    public void updateBackwardBulk(PackageInfo packet, long tsOflastBulkInOther) {
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

    ////////////////////////////


    public void updateActiveIdleTime(long currentTime, long threshold) {
        if ((currentTime - this.endActiveTime) > threshold) {
            if ((this.endActiveTime - this.startActiveTime) > 0) {
                this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
            }
            this.flowIdle.addValue(currentTime - this.endActiveTime);
            this.startActiveTime = currentTime;
        }
        this.endActiveTime = currentTime;
    }

    public int packetCount() {
        if (isBidirectional) {
            return (this.forward.size() + this.backward.size());
        } else {
            return this.forward.size();
        }
    }

    public long getFlowStartTime() {
        return flowStartTime;
    }

    public String getFlowId() {
        return flowId;
    }

    public String dumpFlowBasedFeaturesEx() {
        StringBuilder dump = new StringBuilder();

        dump.append(flowId).append(SEPARATOR);                                        //1
        dump.append(FormatUtils.ip(src)).append(SEPARATOR);                        //2
        dump.append(srcPort).append(SEPARATOR);                                //3
        dump.append(FormatUtils.ip(dst)).append(SEPARATOR);                        //4
        dump.append(dstPort).append(SEPARATOR);                                //5
        dump.append(protocol).append(SEPARATOR);                                //6

        String starttime = DateFormatter.convertMilliseconds2String(flowStartTime / 1000L, "dd/MM/yyyy hh:mm:ss a");
        dump.append(starttime).append(SEPARATOR);                                    //7

        long flowDuration = flowLastSeen - flowStartTime;
        dump.append(flowDuration).append(SEPARATOR);                                //8

        dump.append(fwdPktStats.getN()).append(SEPARATOR);                            //9
        dump.append(bwdPktStats.getN()).append(SEPARATOR);                            //10
        dump.append(fwdPktStats.getSum()).append(SEPARATOR);                        //11
        dump.append(bwdPktStats.getSum()).append(SEPARATOR);                        //12

        if (fwdPktStats.getN() > 0L) {
            dump.append(fwdPktStats.getMax()).append(SEPARATOR);                    //13
            dump.append(fwdPktStats.getMin()).append(SEPARATOR);                    //14
            dump.append(fwdPktStats.getMean()).append(SEPARATOR);                    //15
            dump.append(fwdPktStats.getStandardDeviation()).append(SEPARATOR);        //16
        } else {
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }

        if (bwdPktStats.getN() > 0L) {
            dump.append(bwdPktStats.getMax()).append(SEPARATOR);                    //17
            dump.append(bwdPktStats.getMin()).append(SEPARATOR);                    //18
            dump.append(bwdPktStats.getMean()).append(SEPARATOR);                    //19
            dump.append(bwdPktStats.getStandardDeviation()).append(SEPARATOR);        //20
        } else {
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }
        dump.append(((double) (forwardBytes + backwardBytes)) / ((double) flowDuration / 1000000L)).append(SEPARATOR);//21
        dump.append(((double) packetCount()) / ((double) flowDuration / 1000000L)).append(SEPARATOR);//22
        dump.append(flowIAT.getMean()).append(SEPARATOR);                            //23
        dump.append(flowIAT.getStandardDeviation()).append(SEPARATOR);                //24
        dump.append(flowIAT.getMax()).append(SEPARATOR);                            //25
        dump.append(flowIAT.getMin()).append(SEPARATOR);                            //26

        if (this.forward.size() > 1) {
            dump.append(forwardIAT.getSum()).append(SEPARATOR);                        //27
            dump.append(forwardIAT.getMean()).append(SEPARATOR);                    //28
            dump.append(forwardIAT.getStandardDeviation()).append(SEPARATOR);        //29
            dump.append(forwardIAT.getMax()).append(SEPARATOR);                        //30
            dump.append(forwardIAT.getMin()).append(SEPARATOR);                        //31

        } else {
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }
        if (this.backward.size() > 1) {
            dump.append(backwardIAT.getSum()).append(SEPARATOR);                    //32
            dump.append(backwardIAT.getMean()).append(SEPARATOR);                    //33
            dump.append(backwardIAT.getStandardDeviation()).append(SEPARATOR);        //34
            dump.append(backwardIAT.getMax()).append(SEPARATOR);                    //35
            dump.append(backwardIAT.getMin()).append(SEPARATOR);                    //36
        } else {
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }

        dump.append(fPSH_cnt).append(SEPARATOR);                                    //37
        dump.append(bPSH_cnt).append(SEPARATOR);                                    //38
        dump.append(fURG_cnt).append(SEPARATOR);                                    //39
        dump.append(bURG_cnt).append(SEPARATOR);                                    //40

        dump.append(fHeaderBytes).append(SEPARATOR);                                //41
        dump.append(bHeaderBytes).append(SEPARATOR);                                //42
        dump.append(getfPktsPerSecond()).append(SEPARATOR);                            //43
        dump.append(getbPktsPerSecond()).append(SEPARATOR);                            //44


        if (this.forward.size() > 0 || this.backward.size() > 0) {
            dump.append(flowLengthStats.getMin()).append(SEPARATOR);                //45
            dump.append(flowLengthStats.getMax()).append(SEPARATOR);                //46
            dump.append(flowLengthStats.getMean()).append(SEPARATOR);                //47
            dump.append(flowLengthStats.getStandardDeviation()).append(SEPARATOR);    //48
            dump.append(flowLengthStats.getVariance()).append(SEPARATOR);            //49
        } else {//seem to less one
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }

        dump.append(flagCounts.get("FIN").get()).append(SEPARATOR);                 //50
        dump.append(flagCounts.get("SYN").get()).append(SEPARATOR);                 //51
        dump.append(flagCounts.get("RST").get()).append(SEPARATOR);                  //52
        dump.append(flagCounts.get("PSH").get()).append(SEPARATOR);                  //53
        dump.append(flagCounts.get("ACK").get()).append(SEPARATOR);                  //54
        dump.append(flagCounts.get("URG").get()).append(SEPARATOR);                  //55
        dump.append(flagCounts.get("CWR").get()).append(SEPARATOR);                  //56
        dump.append(flagCounts.get("ECE").get()).append(SEPARATOR);                  //57

        dump.append(getDownUpRatio()).append(SEPARATOR);                            //58
        dump.append(getAvgPacketSize()).append(SEPARATOR);                            //59
        dump.append(fAvgSegmentSize()).append(SEPARATOR);                            //60
        dump.append(bAvgSegmentSize()).append(SEPARATOR);                            //61
        //dump.append(fHeaderBytes).append(separator);								//62 dupicate with 41

        dump.append(fAvgBytesPerBulk()).append(SEPARATOR);                            //63
        dump.append(fAvgPacketsPerBulk()).append(SEPARATOR);                        //64
        dump.append(fAvgBulkRate()).append(SEPARATOR);                                //65
        dump.append(fAvgBytesPerBulk()).append(SEPARATOR);                            //66
        dump.append(bAvgPacketsPerBulk()).append(SEPARATOR);                        //67
        dump.append(bAvgBulkRate()).append(SEPARATOR);                                //68

        dump.append(getSflow_fpackets()).append(SEPARATOR);                            //69
        dump.append(getSflow_fbytes()).append(SEPARATOR);                            //70
        dump.append(getSflow_bpackets()).append(SEPARATOR);                            //71
        dump.append(getSflow_bbytes()).append(SEPARATOR);                            //72

        dump.append(Init_Win_bytes_forward).append(SEPARATOR);                        //73
        dump.append(Init_Win_bytes_backward).append(SEPARATOR);                        //74
        dump.append(Act_data_pkt_forward).append(SEPARATOR);                        //75
        dump.append(min_seg_size_forward).append(SEPARATOR);                        //76


        if (this.flowActive.getN() > 0) {
            dump.append(flowActive.getMean()).append(SEPARATOR);                    //77
            dump.append(flowActive.getStandardDeviation()).append(SEPARATOR);        //78
            dump.append(flowActive.getMax()).append(SEPARATOR);                        //79
            dump.append(flowActive.getMin()).append(SEPARATOR);                        //80
        } else {
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }

        if (this.flowIdle.getN() > 0) {
            dump.append(flowIdle.getMean()).append(SEPARATOR);                        //81
            dump.append(flowIdle.getStandardDeviation()).append(SEPARATOR);            //82
            dump.append(flowIdle.getMax()).append(SEPARATOR);                        //83
            dump.append(flowIdle.getMin()).append(SEPARATOR);                        //84
        } else {
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
            dump.append(0).append(SEPARATOR);
        }
        dump.append(labelSupplier.get(this));
        return dump.toString();
    }
}

class MutableInt {
    int value = 0; // note that we start at 1 since we're counting

    public void increment() {
        ++value;
    }

    public int get() {
        return value;
    }


}
