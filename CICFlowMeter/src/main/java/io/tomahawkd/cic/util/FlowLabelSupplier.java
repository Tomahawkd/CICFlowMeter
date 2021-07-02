package io.tomahawkd.cic.util;

import io.tomahawkd.cic.flow.Flow;

@FunctionalInterface
public interface FlowLabelSupplier {

    String get(Flow flow);
}
