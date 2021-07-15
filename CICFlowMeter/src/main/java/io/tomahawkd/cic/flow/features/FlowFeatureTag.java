package io.tomahawkd.cic.flow.features;

public enum FlowFeatureTag {

    fid("Flow ID"),                            //1 this index is for feature not for ordinal
    src_ip("Src IP"),                        //2
    src_port("Src Port"),                    //3
    dst_ip("Dst IP"),            //4
    dst_port("Dst Port"),        //5
//    prot("Protocol"),                        //6 no need, all are HTTP packets
    tstp("Timestamp"),                        //7
    fl_dur("Flow Duration"),                //8
    fw_pkt_count("Total Fwd Packets"),                            //9
    bw_pkt_count("Total Bwd Packets"),                //10
    fw_pkt_len_total("Total Len Fwd Packets"),        //11
    bw_pkt_len_total("Total Len Bwd Packets"),        //12
    fw_pkt_len_max("Fwd Packet Len Max"),                    //13
    fw_pkt_len_min("Fwd Packet Len Min"),                    //14
    fw_pkt_len_avg("Fwd Packet Len Mean"),                //15
    fw_pkt_len_std("Fwd Packet Len Std"),                    //16
    bw_pkt_len_max("Bwd Packet Len Max"),                    //17
    bw_pkt_len_min("Bwd Packet Len Min"),                    //18
    bw_pkt_len_avg("Bwd Packet Len Mean"),                //19
    bw_pkt_len_std("Bwd Packet Len Std"),                    //20
    fl_byt_s("Flow Bytes/s"),                                //21
    fl_pkt_s("Flow Packets/s"),                            //22
    fl_iat_avg("Flow IAT Mean"),                                    //23
    fl_iat_std("Flow IAT Std"),                                    //24
    fl_iat_max("Flow IAT Max"),                                    //25
    fl_iat_min("Flow IAT Min"),                                    //26
    fw_iat_tot("Fwd IAT Tot"),                                    //27
    fw_iat_avg("Fwd IAT Mean"),                                    //28
    fw_iat_std("Fwd IAT Std"),                                        //29
    fw_iat_max("Fwd IAT Max"),                                        //30
    fw_iat_min("Fwd IAT Min"),                                        //31
    bw_iat_tot("Bwd IAT Tot"),                                    //32
    bw_iat_avg("Bwd IAT Mean"),                                    //33
    bw_iat_std("Bwd IAT Std"),                                        //34
    bw_iat_max("Bwd IAT Max"),                                        //35
    bw_iat_min("Bwd IAT Min"),                                        //36
    fw_psh_flag("Fwd PSH Flags"),                                    //37
    bw_psh_flag("Bwd PSH Flags"),                                    //38
    fw_urg_flag("Fwd URG Flags"),                                    //39
    bw_urg_flag("Bwd URG Flags"),                                    //40
    fw_hdr_len("Fwd Header Len"),                            //41
    bw_hdr_len("Bwd Header Len"),                            //42
    fw_pkt_s("Fwd Packets/s"),                            //43
    bw_pkt_s("Bwd Packets/s"),                            //44
    pkt_len_min("Packet Len Min"),                            //45
    pkt_len_max("Packet Len Max"),                            //46
    pkt_len_avg("Packet Len Mean"),                        //47
    pkt_len_std("Packet Len Std"),                            //48
    pkt_len_var("Packet Len Var"),        //49
    fin_cnt("FIN Flag Count"),                //50
    syn_cnt("SYN Flag Count"),                //51
    rst_cnt("RST Flag Count"),                //52
    psh_cnt("PSH Flag Count"),                //53
    ack_cnt("ACK Flag Count"),                //54
    urg_cnt("URG Flag Count"),                //55
    cwr_cnt("CWR Flag Count"),                //56
    ece_cnt("ECE Flag Count"),                //57
    down_up_ratio("Down/Up Ratio"),                //58
    pkt_size_avg("Packet Size Avg"),            //59
    fw_seg_avg("Fwd Seg Size Avg"),        //60
    bw_seg_avg("Bwd Seg Size Avg"),        //61
    fw_byt_blk_avg("Fwd Bytes/b Avg"),            //63   62 is duplicated with 41,so has been deleted
    fw_pkt_blk_avg("Fwd Packets/b Avg"),        //64
    fw_blk_rate_avg("Fwd Bulk Rate Avg"),            //65
    bw_byt_blk_avg("Bwd Bytes/b Avg"),            //66
    bw_pkt_blk_avg("Bwd Packets/b Avg"),        //67
    bw_blk_rate_avg("Bwd Bulk Rate Avg"),            //68
    subfl_fw_pkt("Subflow Fwd Packets"),            //69 not available
    subfl_fw_byt("Subflow Fwd Bytes"),            //70
    subfl_bw_pkt("Subflow Bwd Packets"),            //71
    subfl_bw_byt("Subflow Bwd Bytes"),            //72
    fw_win_byt("Init Fwd Win Bytes"),        //73
    bw_win_byt("Init Bwd Win Bytes"),        //74
    fw_act_pkt("Fwd Act Data Packets"),            //75
    fw_hdr_min("Fwd Seg Size Min"),        //76
    atv_avg("Active Mean"),                    //77
    atv_std("Active Std"),                    //78
    atv_max("Active Max"),                    //79
    atv_min("Active Min"),                    //80
    idl_avg("Idle Mean"),                    //81
    idl_std("Idle Std"),                    //82
    idl_max("Idle Max"),                    //83
    idl_min("Idle Min"),                    //84

    // HTTP layer features
    request_packet_count("Request Packet Count"),
    content_length_avg("Content Length Avg"),
    content_length_std("Content Length Std"),
    content_length_max("Content Length Max"),
    content_length_min("Content Length Min"),
    content_length_total("Content Length Total"),
    req_content_length_avg("Request Content Length Avg"),
    req_content_length_std("Request Content Length Std"),
    req_content_length_max("Request Content Length Max"),
    req_content_length_min("Request Content Length Min"),
    req_content_length_total("Request Content Length Total"),
    res_content_length_avg("Response Content Length Avg"),
    res_content_length_std("Response Content Length Std"),
    res_content_length_max("Response Content Length Max"),
    res_content_length_min("Response Content Length Min"),
    res_content_length_total("Response Content Length Total"),
    keep_alive_packet_ratio("Keep Alive Packet/Packets"),
    method_get_count("Total GET method count"),
    method_post_count("Total POST method count"),
    referer_count("Total referer count"),

    Label("Label");                    //85

    private final String name;

    FlowFeatureTag(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }

}
