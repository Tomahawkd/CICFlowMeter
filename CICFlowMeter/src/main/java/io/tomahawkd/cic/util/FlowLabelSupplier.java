package io.tomahawkd.cic.util;

import io.tomahawkd.cic.jnetpcap.BasicFlow;

@FunctionalInterface
public interface FlowLabelSupplier {

    String get(BasicFlow flow);
}
