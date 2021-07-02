package io.tomahawkd.cic.flow;

import io.tomahawkd.cic.data.PacketInfo;

public interface FlowFeature {

    String SEPARATOR = ",";

    String headers();

    String exportData();

    int columnCount();

    void addPacket(PacketInfo info, boolean fwd);
}
