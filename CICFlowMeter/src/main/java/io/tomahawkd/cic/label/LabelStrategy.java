package io.tomahawkd.cic.label;

import io.tomahawkd.cic.flow.Flow;

@FunctionalInterface
public interface LabelStrategy {

    String get(Flow flow);
}
