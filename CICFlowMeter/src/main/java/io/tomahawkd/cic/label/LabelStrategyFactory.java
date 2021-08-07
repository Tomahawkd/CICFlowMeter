package io.tomahawkd.cic.label;

import io.tomahawkd.cic.source.LocalFile;

public abstract class LabelStrategyFactory {

    public LabelStrategy getStrategy(LocalFile file) {
        return LabelStrategy.NONE;
    }
}
