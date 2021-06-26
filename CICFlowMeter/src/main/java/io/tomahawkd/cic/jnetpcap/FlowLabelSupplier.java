package io.tomahawkd.cic.jnetpcap;

@FunctionalInterface
public interface FlowLabelSupplier {

    String get(BasicFlow flow);
}
