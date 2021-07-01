package io.tomahawkd.cic.util;

import io.tomahawkd.cic.jnetpcap.BasicFlow;

public interface FlowGenListener {
    void onFlowGenerated(BasicFlow flow);
}
