package io.tomahawkd.cic.label;

import io.tomahawkd.cic.flow.Flow;

@FunctionalInterface
public interface LabelStrategy {

    String getLabel(Flow flow);

    LabelStrategy NONE = null;
    LabelStrategy DEFAULT = f -> "NO_LABEL";
}
